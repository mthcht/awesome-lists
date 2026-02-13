rule Trojan_Win64_PowDow_SXB_2147963018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PowDow.SXB!MTB"
        threat_id = "2147963018"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PowDow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {33 d2 ff 15 ?? ?? ?? ?? 48 8b 55 d8 48 83 fa 10 72 ?? 48 8b 4d c0 48 ff c2 48 8b c1 48 81 fa 00 10 00 00 72 ?? 48 8b 49 f8 48 83 c2 27 48 2b c1 48 83 c0 f8 48 83 f8 1f 0f 87 f9}  //weight: 30, accuracy: Low
        $x_10_2 = {48 8d 4d a0 48 83 7d 18 10 0f 10 00 48 0f 43 55 00 0f 11 45 a0 0f 10 48 10 0f 11 4d b0 48 89 58 10}  //weight: 10, accuracy: High
        $x_5_3 = "powershell.exe -WindowStyle Hidden -Exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

