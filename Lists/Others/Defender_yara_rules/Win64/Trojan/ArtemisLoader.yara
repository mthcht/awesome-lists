rule Trojan_Win64_ArtemisLoader_NR_2147964652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ArtemisLoader.NR!MTB"
        threat_id = "2147964652"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ArtemisLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 44 24 10 8b 00 c1 e0 08 48 8b 4c 24 08 8b 09 0f af c8 8b c1 8b c0 48 8b 4c 24 18 8b 09 48 8b 54 24 08 8b 12 48 0f af ca 48 c1 e9 18 48 03 c1 89 04 24 8b 04 24 48 83 c4 28}  //weight: 2, accuracy: High
        $x_1_2 = "SeImpersonatePrivilege" wide //weight: 1
        $x_1_3 = "Runas" wide //weight: 1
        $x_1_4 = "ReadProcessMemory" ascii //weight: 1
        $x_1_5 = "winlogon.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

