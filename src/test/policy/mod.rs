use crate::*;

#[test]
fn test_unlock_guac_policy_json() {
    let raw_policy = r#"{"ExperienceChatAvailability":"regionLocked","CanUsePlatformChat":false,"CanUsePlatformChat2":false,"CountryCode":"FR","Username":"TestPlayer"}"#;
    let mut raw_app_storage = serde_json::json!({
        "Username": "TestPlayer",
        "AppConfiguration": serde_json::to_string(&serde_json::json!({
            "GUAC:-1:app-policy": raw_policy,
            "GUAC:600860999:app-policy": raw_policy,
            "OtherSetting": 123
        })).unwrap()
    });

    let modified = update_guac_policy_in_value(&mut raw_app_storage);
    assert!(modified);

    // Verify chat fields unlocked
    let app_config_str = raw_app_storage["AppConfiguration"].as_str().unwrap();
    let app_config: serde_json::Value = serde_json::from_str(app_config_str).unwrap();
    let p1: serde_json::Value =
        serde_json::from_str(app_config["GUAC:-1:app-policy"].as_str().unwrap()).unwrap();
    assert_eq!(p1["ExperienceChatAvailability"], "available");
    assert_eq!(p1["CanUsePlatformChat"], true);
    assert_eq!(p1["CanUsePlatformChat2"], true);
    assert_eq!(p1["CountryCode"], "FR");
    assert_eq!(raw_app_storage["Username"], "TestPlayer");

    // Second call should return false (already unlocked)
    let modified_again = update_guac_policy_in_value(&mut raw_app_storage);
    assert!(!modified_again);
}

#[test]
fn test_unlock_guac_policy_fresh_install_keys_absent() {
    // When Roblox creates a default policy without any chat keys present initially
    let mut raw_app_storage = serde_json::json!({
        "AppConfiguration": serde_json::to_string(&serde_json::json!({
            "GUAC:-1:app-policy": "{}",
        })).unwrap()
    });

    let modified = update_guac_policy_in_value(&mut raw_app_storage);
    assert!(
        modified,
        "Must insert chat keys even when missing from initial policy"
    );

    let app_config_str = raw_app_storage["AppConfiguration"].as_str().unwrap();
    let app_config: serde_json::Value = serde_json::from_str(app_config_str).unwrap();
    let p: serde_json::Value =
        serde_json::from_str(app_config["GUAC:-1:app-policy"].as_str().unwrap()).unwrap();
    assert_eq!(p["ExperienceChatAvailability"], "available");
    assert_eq!(p["CanUsePlatformChat"], true);
    assert_eq!(p["CanUsePlatformChat2"], true);
    assert_eq!(p["CanSeeChatTab"], true);
    assert_eq!(p["CanSeeChatTab2"], true);
    assert_eq!(p["canSeeChatTerminology"], true);
}

#[test]
fn test_ensure_file_writable_restores_write_permissions() {
    let temp_dir =
        std::env::temp_dir().join(format!("warp_min_writable_{}", rand::random::<u32>()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let test_file = temp_dir.join("appStorage.json");

    std::fs::write(&test_file, b"{\"test\": 123}").unwrap();

    // 1. Set file as READ-ONLY
    let meta = std::fs::metadata(&test_file).unwrap();
    let mut perms = meta.permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&test_file, perms).unwrap();

    // Verify it is currently read-only
    assert!(
        std::fs::metadata(&test_file)
            .unwrap()
            .permissions()
            .readonly()
    );

    // 2. Run ensure_file_writable
    let restored = ensure_file_writable(&test_file).expect("ensure_file_writable must succeed");
    assert!(restored, "Should report that permissions were restored");

    // 3. Verify it is no longer read-only
    assert!(
        !std::fs::metadata(&test_file)
            .unwrap()
            .permissions()
            .readonly(),
        "File must no longer be READ-ONLY"
    );

    // 4. Verify opening for writing succeeds (LocalStorageManager will not error)
    let write_res = std::fs::OpenOptions::new().write(true).open(&test_file);
    assert!(write_res.is_ok(), "Opening file for writing must succeed");

    // 5. Calling again returns false (already writable)
    let second_run = ensure_file_writable(&test_file).expect("second run must succeed");
    assert!(
        !second_run,
        "Second run should report false since file is already writable"
    );

    // Cleanup
    let _ = std::fs::remove_dir_all(&temp_dir);
}
