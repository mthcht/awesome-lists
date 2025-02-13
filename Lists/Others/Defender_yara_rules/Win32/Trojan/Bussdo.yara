rule Trojan_Win32_Bussdo_A_2147598166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bussdo.A"
        threat_id = "2147598166"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bussdo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 e2 eb 0a 8b 84 bd ?? ?? ff ff 89 45 fc 8d 85 c8 fe ff ff 50 ff 15 ?? ?? 40 00 83 f8 ff 6a 0a 6a 65 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bussdo_A_2147598167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bussdo.A!dll"
        threat_id = "2147598167"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bussdo"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 eb 2a 80 f9 0d 75 1d 80 bc 05 ?? f9 ff ff 0a 75 13 38 8c 05 ?? f9 ff ff 75 0a 80 bc 05}  //weight: 1, accuracy: Low
        $x_1_2 = {59 99 b9 e9 03 00 00 f7 f9 81 c2 e8 03 00 00 52 ff d6 66 89 45 ?? 8d 45 ?? 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

