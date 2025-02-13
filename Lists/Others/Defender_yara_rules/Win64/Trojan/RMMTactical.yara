rule Trojan_Win64_RMMTactical_A_2147830452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RMMTactical.A!MTB"
        threat_id = "2147830452"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RMMTactical"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 69 74 68 75 62 2e 63 6f 6d 2f 77 68 31 74 65 39 30 39 2f 72 6d 6d 61 67 65 6e 74 2f 72 65 6c 65 61 73 65 73 2f 64 6f 77 6e 6c 6f 61 64 2f 76 31 2e ?? 2e 30 2f 77 69 6e 61 67 65 6e 74 2d 76 31 2e ?? 2e 30 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = "Tactical RMM Installer" wide //weight: 1
        $x_1_3 = "v2.0.3.0" wide //weight: 1
        $x_1_4 = "rmm.exe" wide //weight: 1
        $x_1_5 = "installer.go" wide //weight: 1
        $x_1_6 = "1278BEHIJOQXZ\\bexz" ascii //weight: 1
        $x_1_7 = "AmidaWare LLC" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

