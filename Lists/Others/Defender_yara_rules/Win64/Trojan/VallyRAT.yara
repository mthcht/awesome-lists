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

