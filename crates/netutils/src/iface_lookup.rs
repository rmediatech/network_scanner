use crate::iface::{list_interfaces, IfaceError, NetworkInterface};
use std::net::Ipv4Addr;

/// Finds an interface by name.
pub fn get_interface_by_name(name: &str) -> Result<NetworkInterface, IfaceError> {
    let interfaces = list_interfaces()?;
    interfaces
        .into_iter()
        .find(|iface| iface.name == name)
        .ok_or(IfaceError::NotFound)
}

/// Finds an interface by index.
pub fn get_interface_by_index(index: u32) -> Result<NetworkInterface, IfaceError> {
    let interfaces = list_interfaces()?;
    interfaces
        .into_iter()
        .find(|iface| iface.index == index)
        .ok_or(IfaceError::NotFound)
}

/// Finds an interface by MAC address.
pub fn get_interface_by_mac(mac: [u8; 6]) -> Result<NetworkInterface, IfaceError> {
    let interfaces = list_interfaces()?;
    interfaces
        .into_iter()
        .find(|iface| iface.mac == Some(mac))
        .ok_or(IfaceError::NotFound)
}

/// Finds an interface by IPv4 address.
pub fn get_interface_by_ipv4(ipv4: Ipv4Addr) -> Result<NetworkInterface, IfaceError> {
    let interfaces = list_interfaces()?;
    interfaces
        .into_iter()
        .find(|iface| iface.ipv4 == Some(ipv4))
        .ok_or(IfaceError::NotFound)
}

/// Finds an interface by name or index.
pub fn get_interface_by_name_or_index(
    name: Option<&str>,
    index: Option<u32>,
) -> Result<NetworkInterface, IfaceError> {
    if let Some(name) = name {
        get_interface_by_name(name)
    } else if let Some(index) = index {
        get_interface_by_index(index)
    } else {
        Err(IfaceError::NotFound)
    }
}

/// Finds an interface by MAC address or IPv4 address.
pub fn get_interface_by_mac_or_ipv4(
    mac: Option<[u8; 6]>,
    ipv4: Option<Ipv4Addr>,
) -> Result<NetworkInterface, IfaceError> {
    if let Some(mac) = mac {
        get_interface_by_mac(mac)
    } else if let Some(ipv4) = ipv4 {
        get_interface_by_ipv4(ipv4)
    } else {
        Err(IfaceError::NotFound)
    }
}

/// Finds an interface by name, index, MAC address, or IPv4 address.
pub fn get_interface_by_name_index_mac_ipv4(
    name: Option<&str>,
    index: Option<u32>,
    mac: Option<[u8; 6]>,
    ipv4: Option<Ipv4Addr>,
) -> Result<NetworkInterface, IfaceError> {
    if let Some(name) = name {
        get_interface_by_name(name)
    } else if let Some(index) = index {
        get_interface_by_index(index)
    } else if let Some(mac) = mac {
        get_interface_by_mac(mac)
    } else if let Some(ipv4) = ipv4 {
        get_interface_by_ipv4(ipv4)
    } else {
        Err(IfaceError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iface::get_default_interface;

    #[test]
    fn test_list_interfaces_not_empty() {
        let interfaces = list_interfaces().expect("Should list interfaces");
        assert!(
            !interfaces.is_empty(),
            "There should be at least one interface"
        );
    }

    #[test]
    fn test_get_default_interface_is_up_and_has_ipv4() {
        let iface = get_default_interface().expect("Should find a default interface");
        assert!(iface.up, "Default interface should be up");
        assert!(
            iface.ipv4.is_some(),
            "Default interface should have an IPv4 address"
        );
        assert!(
            !iface.name.starts_with("lo"),
            "Default interface should not be loopback"
        );
    }

    #[test]
    fn test_get_interface_by_name_roundtrip() {
        let interfaces = list_interfaces().expect("Should list interfaces");
        let iface = interfaces
            .iter()
            .find(|iface| iface.up && iface.ipv4.is_some() && !iface.name.starts_with("lo"))
            .expect("Should have at least one up, non-loopback interface with IPv4");
        let by_name = get_interface_by_name(&iface.name).expect("Should find interface by name");
        assert_eq!(iface.name, by_name.name);
        assert_eq!(iface.index, by_name.index);
    }

    #[test]
    fn test_get_interface_by_index_roundtrip() {
        let interfaces = list_interfaces().expect("Should list interfaces");
        let iface = interfaces
            .iter()
            .find(|iface| iface.up && iface.ipv4.is_some() && !iface.name.starts_with("lo"))
            .expect("Should have at least one up, non-loopback interface with IPv4");
        let by_index = get_interface_by_index(iface.index).expect("Should find interface by index");
        assert_eq!(iface.name, by_index.name);
        assert_eq!(iface.index, by_index.index);
    }

    #[test]
    fn test_get_interface_by_mac_or_ipv4() {
        let interfaces = list_interfaces().expect("Should list interfaces");
        let iface = interfaces.iter().find(|iface| {
            iface.up && iface.ipv4.is_some() && iface.mac.is_some() && !iface.name.starts_with("lo")
        });
        if let Some(iface) = iface {
            let by_mac = get_interface_by_mac_or_ipv4(iface.mac, None).expect("Should find by MAC");
            assert_eq!(iface.mac, by_mac.mac);
            let by_ipv4 =
                get_interface_by_mac_or_ipv4(None, iface.ipv4).expect("Should find by IPv4");
            assert_eq!(iface.ipv4, by_ipv4.ipv4);
        }
    }

    #[test]
    fn test_get_interface_by_name_index_mac_ipv4() {
        let interfaces = list_interfaces().expect("Should list interfaces");
        let iface = interfaces.iter().find(|iface| {
            iface.up && iface.ipv4.is_some() && iface.mac.is_some() && !iface.name.starts_with("lo")
        });
        if let Some(iface) = iface {
            let by_name = get_interface_by_name_index_mac_ipv4(Some(&iface.name), None, None, None)
                .expect("Should find by name");
            assert_eq!(iface.name, by_name.name);

            let by_index =
                get_interface_by_name_index_mac_ipv4(None, Some(iface.index), None, None)
                    .expect("Should find by index");
            assert_eq!(iface.index, by_index.index);

            let by_mac = get_interface_by_name_index_mac_ipv4(None, None, iface.mac, None)
                .expect("Should find by MAC");
            assert_eq!(iface.mac, by_mac.mac);

            let by_ipv4 = get_interface_by_name_index_mac_ipv4(None, None, None, iface.ipv4)
                .expect("Should find by IPv4");
            assert_eq!(iface.ipv4, by_ipv4.ipv4);
        }
    }

    #[test]
    fn test_get_interface_by_name_not_found() {
        let result = get_interface_by_name("definitely_not_a_real_interface_name_12345");
        assert!(matches!(result, Err(IfaceError::NotFound)));
    }
}
