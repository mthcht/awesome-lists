rule Trojan_Win32_Flatterly_A_2147751923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Flatterly.A!dha"
        threat_id = "2147751923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Flatterly"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "::googlechromeupdate" ascii //weight: 1
        $x_1_2 = "C:\\ProgramData\\t.txt" wide //weight: 1
        $x_1_3 = "Execute!" wide //weight: 1
        $x_1_4 = "DNSClient.dll" wide //weight: 1
        $x_1_5 = "DNSClien.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

