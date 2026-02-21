use std::process::Command;
use std::sync::Arc;
use tauri::Manager;
use tracing::{info, warn, error};

// Interface name sanitization
fn sanitize_interface_name(name: &str) -> Result<String, String> {
    if name.len() > 15 {
        return Err("Interface name too long".into());
    }
    if !name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return Err("Invalid interface name".into());
    }
    Ok(name.to_string())
}

// Platform-specific privileged command execution
#[cfg(target_os = "linux")]
fn run_privileged_command(cmd: &str, args: &[&str]) -> Result<std::process::Output, String> {
    // First try without elevation (in case already root)
    let output = Command::new(cmd).args(args).output();
    
    match output {
        Ok(o) if o.status.success() => Ok(o),
        _ => {
            // Try with pkexec for graphical privilege escalation
            Command::new("pkexec")
                .arg(cmd)
                .args(args)
                .output()
                .map_err(|e| format!("Failed to run privileged command: {}", e))
        }
    }
}

#[cfg(target_os = "macos")]
fn run_privileged_command(cmd: &str, args: &[&str]) -> Result<std::process::Output, String> {
    // macOS uses osascript for privilege escalation
    // Build shell-escaped command to prevent injection attacks
    fn shell_escape(s: &str) -> String {
        // Use single quotes, escaping any embedded single quotes
        // This is the safest shell escaping method
        format!("'{}'", s.replace("'", "'\\''"))
    }
    
    let mut command_parts = vec![shell_escape(cmd)];
    for arg in args {
        command_parts.push(shell_escape(arg));
    }
    
    let script = format!(
        "do shell script {} with administrator privileges",
        command_parts.join(" ")
    );
    
    Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .output()
        .map_err(|e| format!("Failed to run privileged command: {}", e))
}

#[cfg(target_os = "windows")]
fn run_command(cmd: &str, args: &[&str]) -> Result<std::process::Output, String> {
    // On Windows, netsh commands work without elevation if app has appropriate permissions
    // For firewall rules, the app should be run as administrator or have UAC consent
    Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run command '{}': {}", cmd, e))
}

#[cfg(target_os = "windows")]
fn run_powershell(script: &str) -> Result<std::process::Output, String> {
    // Run PowerShell command
    Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|e| format!("Failed to run PowerShell: {}", e))
}

#[cfg(target_os = "windows")]
fn is_elevated() -> bool {
    // Check if running with administrator privileges
    let output = run_powershell(
        "(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
    );
    
    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).trim().to_string();
            stdout == "True"
        },
        Err(_) => false
    }
}

// Windows firewall rule names
#[cfg(target_os = "windows")]
const FIREWALL_RULE_BLOCK: &str = "VPNht Kill Switch Block";
#[cfg(target_os = "windows")]
const FIREWALL_RULE_ALLOW_WG: &str = "VPNht Kill Switch Allow WireGuard";

pub struct KillSwitch {
    enabled: bool,
    firewall_rules: Vec<String>,
    #[cfg(target_os = "windows")]
    wireguard_interface: Option<String>,
}

impl KillSwitch {
    pub fn new() -> Self {
        Self {
            enabled: false,
            firewall_rules: Vec::new(),
            #[cfg(target_os = "windows")]
            wireguard_interface: None,
        }
    }

    pub fn enable(&mut self) -> Result<(), String> {
        if self.enabled {
            return Ok(());
        }
        
        #[cfg(target_os = "linux")]
        self.setup_iptables()?;
        
        #[cfg(target_os = "windows")]
        self.setup_wfp()?;
        
        #[cfg(target_os = "macos")]
        self.setup_pf()?;
        
        self.enabled = true;
        info!("Kill Switch enabled");
        Ok(())
    }

    pub fn disable(&mut self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        
        #[cfg(target_os = "linux")]
        self.teardown_iptables()?;
        
        #[cfg(target_os = "windows")]
        self.teardown_wfp()?;
        
        #[cfg(target_os = "macos")]
        self.teardown_pf()?;
        
        self.enabled = false;
        info!("Kill Switch disabled");
        Ok(())
    }

    pub fn on_vpn_disconnect(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        
        info!("VPN disconnected - activating Kill Switch");
        #[cfg(target_os = "linux")]
        self.block_all_traffic_linux()?;
        
        Ok(())
    }

    // Linux implementation
    #[cfg(target_os = "linux")]
    fn setup_iptables(&mut self) -> Result<(), String> {
        // Save current rules
        let output = run_privileged_command("iptables", &["-L", "-n", "-v"])?;
        
        self.firewall_rules = String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|s| s.to_string())
            .collect();
        
        info!("Saved {} iptables rules", self.firewall_rules.len());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn teardown_iptables(&mut self) -> Result<(), String> {
        // Restore saved rules
        for rule in &self.firewall_rules {
            if rule.contains("vpnht-killswitch") {
                let args: Vec<&str> = rule.split_whitespace().collect();
                run_privileged_command("iptables", &args)?;
            }
        }
        
        self.firewall_rules.clear();
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn block_all_traffic_linux(&self) -> Result<(), String> {
        // Block all non-VPN traffic using privileged command
        run_privileged_command(
            "iptables", 
            &["-A", "OUTPUT", "-m", "mark", "!", "--mark", "0xca6c", "-m", "addrtype", "!", "--dst-type", "LOCAL", "-j", "DROP", "-m", "comment", "--comment", "vpnht-killswitch"]
        )?;
        
        run_privileged_command(
            "iptables", 
            &["-A", "INPUT", "-m", "mark", "!", "--mark", "0xca6c", "-j", "DROP", "-m", "comment", "--comment", "vpnht-killswitch"]
        )?;
        
        info!("All non-VPN traffic blocked");
        Ok(())
    }

    // Windows implementation using netsh advfirewall
    #[cfg(target_os = "windows")]
    fn setup_wfp(&mut self) -> Result<(), String> {
        info!("Setting up Windows Firewall Kill Switch");
        
        // Check if we have elevation
        if !is_elevated() {
            warn!("Kill Switch may require administrator privileges");
        }

        // Remove any existing rules first (cleanup from previous session)
        self.remove_firewall_rules()?;

        // Find WireGuard interface
        let wg_interface = self.find_wireguard_interface()?;
        if wg_interface.is_some() {
            info!("Found WireGuard interface: {:?}", wg_interface);
        }

        // Create block rule for all outbound traffic
        // netsh advfirewall firewall add rule name="..." dir=out action=block remoteip=any
        let block_output = run_command("netsh", &[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={}", FIREWALL_RULE_BLOCK),
            "dir=out",
            "action=block",
            "remoteip=any",
            "enable=yes",
            "profile=any",
        ])?;

        if !block_output.status.success() {
            let stderr = String::from_utf8_lossy(&block_output.stderr);
            return Err(format!("Failed to create block rule: {}", stderr));
        }
        info!("Created firewall block rule: {}", FIREWALL_RULE_BLOCK);

        // Allow WireGuard interface traffic if found
        if let Some(ref iface) = wg_interface {
            self.wireguard_interface = Some(iface.clone());
            
            // Use PowerShell for interface-specific rule (netsh doesn't support interface filtering)
            let allow_script = format!(
                r#"New-NetFirewallRule -DisplayName '{}' -Direction Outbound -Action Allow -InterfaceAlias '{}' -Enabled True -Profile Any"#,
                FIREWALL_RULE_ALLOW_WG, iface
            );
            
            let allow_output = run_powershell(&allow_script)?;
            if allow_output.status.success() {
                info!("Created firewall allow rule for interface: {}", iface);
            } else {
                warn!("Could not create WireGuard allow rule, block rule still active");
            }
        }

        // Also allow DHCP and DNS for initial connection
        self.allow_essential_traffic()?;

        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn teardown_wfp(&mut self) -> Result<(), String> {
        info!("Tearing down Windows Firewall Kill Switch");
        self.remove_firewall_rules()
    }

    #[cfg(target_os = "windows")]
    fn remove_firewall_rules(&self) -> Result<(), String> {
        // Remove block rule
        let _ = run_command("netsh", &[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={}", FIREWALL_RULE_BLOCK),
        ]);
        info!("Removed firewall block rule");

        // Remove WireGuard allow rule (via PowerShell)
        let remove_script = format!(
            r#"Remove-NetFirewallRule -DisplayName '{}' -ErrorAction SilentlyContinue"#,
            FIREWALL_RULE_ALLOW_WG
        );
        let _ = run_powershell(&remove_script);
        info!("Removed WireGuard allow rule");

        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn find_wireguard_interface(&self) -> Result<Option<String>, String> {
        // Find WireGuard interface using PowerShell
        // Common WireGuard interface names: "wg0", "WireGuard", or any with "wg" prefix
        let script = r#"
            $adapters = Get-NetAdapter | Where-Object { 
                $_.InterfaceDescription -like "*WireGuard*" -or 
                $_.Name -like "wg*" -or 
                $_.Name -like "*WireGuard*"
            }
            if ($adapters) {
                $adapters[0].Name
            }
        "#;
        
        let output = run_powershell(script)?;
        let iface_name = String::from_utf8_lossy(&output.stdout).trim().to_string();
        
        if iface_name.is_empty() {
            Ok(None)
        } else {
            Ok(Some(iface_name))
        }
    }

    #[cfg(target_os = "windows")]
    fn allow_essential_traffic(&self) -> Result<(), String> {
        // Allow DHCP (UDP 67, 68) for network connectivity
        let dhcp_out = run_command("netsh", &[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=VPNht Kill Switch DHCP Out",
            "dir=out",
            "action=allow",
            "protocol=udp",
            "localport=68",
            "remoteport=67",
            "enable=yes",
        ])?;

        // Allow DNS (UDP/TCP 53) for name resolution
        let dns_out = run_command("netsh", &[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=VPNht Kill Switch DNS Out",
            "dir=out",
            "action=allow",
            "protocol=any",
            "remoteport=53",
            "enable=yes",
        ])?;

        info!("Allowed essential traffic (DHCP, DNS)");
        Ok(())
    }
}

impl Drop for KillSwitch {
    fn drop(&mut self) {
        // Ensure firewall rules are cleaned up when KillSwitch is dropped
        if self.enabled {
            #[cfg(target_os = "windows")]
            {
                let _ = self.teardown_wfp();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_interface_name_valid() {
        assert_eq!(sanitize_interface_name("wg0"), Ok("wg0".to_string()));
        assert_eq!(sanitize_interface_name("WireGuard-1"), Ok("WireGuard-1".to_string()));
        assert_eq!(sanitize_interface_name("vpn_test"), Ok("vpn_test".to_string()));
    }

    #[test]
    fn test_sanitize_interface_name_too_long() {
        let long_name = "this_interface_name_is_way_too_long";
        assert!(sanitize_interface_name(long_name).is_err());
    }

    #[test]
    fn test_sanitize_interface_name_invalid_chars() {
        assert!(sanitize_interface_name("wg 0").is_err()); // space
        assert!(sanitize_interface_name("wg@0").is_err()); // @
        assert!(sanitize_interface_name("wg.0").is_err()); // .
    }

    #[test]
    fn test_killswitch_new() {
        let ks = KillSwitch::new();
        assert!(!ks.enabled);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_firewall_rule_names() {
        assert_eq!(FIREWALL_RULE_BLOCK, "VPNht Kill Switch Block");
        assert_eq!(FIREWALL_RULE_ALLOW_WG, "VPNht Kill Switch Allow WireGuard");
    }
}