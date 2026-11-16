rule Trojan_Win64_VallyRAT_RN_2147979833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VallyRAT.RN!MTB"
        threat_id = "2147979833"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VallyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DisableWindowsUpdateAccess" ascii //weight: 1
        $x_1_2 = "netsh advfirewall firewall add rule name=\"Block Windows Update Service\" dir=out" ascii //weight: 1
        $x_1_3 = "Avast Software\\Avast Software" ascii //weight: 1
        $x_1_4 = "Kaspersky Lab" ascii //weight: 1
        $x_1_5 = "PzUWRT4lJzU8GyAJPDUkQD81FkUjNDc1PBsgQzw0" ascii //weight: 1
        $x_1_6 = "VulnerableDriverBlocklistEnable" ascii //weight: 1
        $x_2_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_1_8 = "VGtWUk1WRlVhM2ROUkVGM1RYcEJkMDFFUVhkTlJFRXdUVVJCZDAxRVFYZFNhMX" ascii //weight: 1
        $x_1_9 = "V1ROTlJWRjNUVlJCZUUxRlNYZE9WRUYzVFhwQk5FMVZTa1ZOZWtWM1VX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_VallyRAT_TN_2147979843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VallyRAT.TN!MTB"
        threat_id = "2147979843"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VallyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell\\Manage\\command" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii //weight: 1
        $x_1_3 = "Elevation:Administrator!new:" ascii //weight: 1
        $x_1_4 = "cmd.exe /c" ascii //weight: 1
        $x_1_5 = "Failed to write shellcode to file" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_7 = "VulnerableDriverBlocklistEnable" ascii //weight: 1
        $x_2_8 = "Wlhod2JHOXlaWEl1WlhobElITm9aV3hzT2pvNg==" ascii //weight: 2
        $x_1_9 = "atlTraceWindowing" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_VallyRAT_VN_2147979934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VallyRAT.VN!MTB"
        threat_id = "2147979934"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VallyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\Default\\History-wal" ascii //weight: 1
        $x_1_2 = "Opera Software\\Opera Stable\\History" ascii //weight: 1
        $x_1_3 = "BitDefender" ascii //weight: 1
        $x_1_4 = "SELECT * FROM __EventFilter WHERE Name='SvcHostUpdate" ascii //weight: 1
        $x_2_5 = "|txt.mh/moc.9gnoguohs//:sptth:" ascii //weight: 2
        $x_1_6 = "DisplaySessionContainers.log" ascii //weight: 1
        $x_1_7 = "CLSID\\{%.8X-%.4X-%.4X-%.2X%.2X-%.2X%.2X%.2X%.2X%.2X%.2X" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_VallyRAT_UN_2147980010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VallyRAT.UN!MTB"
        threat_id = "2147980010"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VallyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ":sp|txt.mh/moc.9gnoguohs//:sptth:ru|0:db|0:lk|0:hs|" ascii //weight: 2
        $x_1_2 = "SELECT * FROM __EventFilter WHERE Name='SvcHostUpdate" ascii //weight: 1
        $x_1_3 = "CLSID\\{%.8X-%.4X-%.4X-%.2X%.2X-%.2X%.2X%.2X%.2X%.2X%.2X" ascii //weight: 1
        $x_1_4 = "BitDefender" ascii //weight: 1
        $x_1_5 = "Opera Software\\Opera Stable\\History" ascii //weight: 1
        $x_1_6 = "mcohilncbfahbmgdjkbpemcciiolgcge" ascii //weight: 1
        $x_1_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_VallyRAT_EN_2147980090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VallyRAT.EN!MTB"
        threat_id = "2147980090"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VallyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RemoteController_Outbound_Rule" ascii //weight: 1
        $x_1_2 = "cmd.exe /c" ascii //weight: 1
        $x_2_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_1_4 = "Failed to write shellcode to file" ascii //weight: 1
        $x_1_5 = "Wlhod2JHOXlaWEl1WlhobElITm9aV3hzT2pvNg==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_VallyRAT_IN_2147980435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VallyRAT.IN!MTB"
        threat_id = "2147980435"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VallyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PXFwOzpIEUAlZTNkMnJwfD1ucDs6US5zNTA8" ascii //weight: 1
        $x_1_2 = "write shellcode to file" ascii //weight: 1
        $x_2_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_1_4 = "SeLoadDriverPrivilege" ascii //weight: 1
        $x_1_5 = "Successfully deleted registry key for driver" ascii //weight: 1
        $x_1_6 = "BZAElQjkAeQB5wHkAeQB5AHgAeQB5AHkd5J3kgHkAeR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_VallyRAT_MN_2147980588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VallyRAT.MN!MTB"
        threat_id = "2147980588"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VallyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "There are more things in heaven and earth, Horatio, than are dreamt of in your philosophy" ascii //weight: 2
        $x_1_2 = "NoManOrWomanIsWorthYourTearsAndTheOneWhoIsWontMakeYouCry" ascii //weight: 1
        $x_1_3 = "%8x-%4x-%4x-%2x%2x-%2x%2x%2x%2x%2x%2x" ascii //weight: 1
        $x_1_4 = "VirtualBox" ascii //weight: 1
        $x_1_5 = "Telegram Desktop" ascii //weight: 1
        $x_1_6 = "Sessions\\%d\\BaseNamedObjects\\MMPP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_VallyRAT_ON_2147980735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VallyRAT.ON!MTB"
        threat_id = "2147980735"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VallyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_2 = "SeIncreaseBasePriorityPrivilege" ascii //weight: 1
        $x_1_3 = "/c start \"\" \"%s\" \"%s\"" ascii //weight: 1
        $x_1_4 = "curl.exe\" -L -s -o" ascii //weight: 1
        $x_1_5 = "bitsadmin.exe\" /transfer myJob_%u /download /priority foreground" ascii //weight: 1
        $x_1_6 = "certutil.exe\" -urlcache -split -f" ascii //weight: 1
        $x_4_7 = "C:\\Users\\Administrator\\source\\repos\\MSEdgeWebView\\Release\\MSEdgeWebView.pdb" ascii //weight: 4
        $x_4_8 = "F:\\dd\\vctools\\vc7libs\\ship\\atlmfc\\src\\mfc\\vmware-vdiskmanager\\Release\\vmware-vdiskmanager.pdb" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_VallyRAT_BN_2147982184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VallyRAT.BN!MTB"
        threat_id = "2147982184"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VallyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%08lX-%04X-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X" ascii //weight: 1
        $x_1_2 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_3 = "bitsadmin.exe\" /transfer myJob_%u /download /priority foreground" ascii //weight: 1
        $x_1_4 = "certutil.exe\" -urlcache -split -f" ascii //weight: 1
        $x_4_5 = "C:\\Users\\Administrator\\source\\repos\\MSEdgeWebView\\Release\\MSEdgeWebView.pdb" ascii //weight: 4
        $x_4_6 = {44 00 3a 00 5c 00 61 00 5c 00 5f 00 77 00 6f 00 72 00 6b 00 5c 00 31 00 5c 00 73 00 5c 00 73 00 72 00 63 00 5c 00 76 00 63 00 74 00 6f 00 6f 00 6c 00 73 00 5c 00 56 00 43 00 37 00 4c 00 69 00 62 00 73 00 5c 00 53 00 68 00 69 00 70 00 5c 00 41 00 54 00 4c 00 4d 00 46 00 43 00 5c 00 53 00 72 00 63 00 5c 00 4d 00 46 00 43 00 5c 00 [0-255] 2e 00 70 00 64 00 62 00}  //weight: 4, accuracy: Low
        $x_4_7 = {44 3a 5c 61 5c 5f 77 6f 72 6b 5c 31 5c 73 5c 73 72 63 5c 76 63 74 6f 6f 6c 73 5c 56 43 37 4c 69 62 73 5c 53 68 69 70 5c 41 54 4c 4d 46 43 5c 53 72 63 5c 4d 46 43 5c [0-255] 2e 70 64 62}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_VallyRAT_DN_2147982185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VallyRAT.DN!MTB"
        threat_id = "2147982185"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VallyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "// SIG // BAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRQwEgYD" ascii //weight: 2
        $x_1_2 = "// SIG // VQQHEwtTYW50YSBDbGFyYTEbMBkGA1UEChMSTlZJRElB" ascii //weight: 1
        $x_1_3 = "// SIG // IENvcnBvcmF0aW9uMRAwDgYDVQQLEwcyMDA4QjlGMRsw" ascii //weight: 1
        $x_1_4 = "// SIG // GQYDVQQDExJOVklESUEgQ29ycG9yYXRpb24wggGiMA0G" ascii //weight: 1
        $x_1_5 = "// SIG // CSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCmtnTBLG0s" ascii //weight: 1
        $x_1_6 = "// SIG // ZOXkJaWS5x94IYJAnMZRQ0f/mrPKFKjs7VxT66RljGZM" ascii //weight: 1
        $x_1_7 = "// SIG // jrtOjDYj8nFG1TIeqW/JyY69FC6aj8Hfu5T82dUQQ4lI" ascii //weight: 1
        $x_1_8 = "// SIG // s0ry1u0JHFa7XKWk8y1eTdGns6o9ZV8BVlNTFRmp9LV5" ascii //weight: 1
        $x_1_9 = "// SIG // nK0gGgBSRhegoUG5oeZbRHiXfvWUHpymh/nmGSDwkuBZ" ascii //weight: 1
        $x_1_10 = "// SIG // PbEHn7rh9OtPqDeGjBNYhsjy/5f3C8F53xhZH8tE3ZmQ" ascii //weight: 1
        $x_1_11 = "// SIG // zviBxEYXI6qwBSn2ILA5Q7FJznOrJockb9URYLMdlu9z" ascii //weight: 1
        $x_1_12 = "// SIG // M7be1LGfNajkXWQ0ys7RspKECAv2GKNN4iOwX6LUzWPX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

