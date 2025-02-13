rule Trojan_WinNT_Zegost_B_2147662337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Zegost.B!rootkit"
        threat_id = "2147662337"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Zegost"
        severity = "Critical"
        info = "rootkit: rootkit component of that malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {eb 09 8b 45 a8 83 c0 01 89 45 a8 81 7d a8 49 01 00 00 0f 83 08 01 00 00 8b 4d a8 6b c9 3c 81 c1 00 f0 01 00 51 8d 55 ac 52 ff 15}  //weight: 5, accuracy: High
        $x_5_2 = {75 df 8b 95 54 ff ff ff 2b 95 50 ff ff ff d1 fa 89 95 48 ff ff ff 83 bd 48 ff ff ff 0a 76 25 8b 45 a8 6b c0 3c 05}  //weight: 5, accuracy: High
        $x_5_3 = {68 4f 46 4e 49 68 cc a8 3b 00 6a 00 ff}  //weight: 5, accuracy: High
        $x_5_4 = "\\antivshlp32.dll" wide //weight: 5
        $x_1_5 = "tmproxy.exe" wide //weight: 1
        $x_1_6 = "vir.exe" wide //weight: 1
        $x_1_7 = "zonealarm.exe" wide //weight: 1
        $x_1_8 = "avgnt.exe" wide //weight: 1
        $x_1_9 = "kasmain.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 2 of ($x_1_*))) or
            ((4 of ($x_5_*))) or
            (all of ($x*))
        )
}

