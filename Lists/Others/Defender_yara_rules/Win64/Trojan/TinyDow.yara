rule Trojan_Win64_TinyDow_A_2147838237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TinyDow.A!MTB"
        threat_id = "2147838237"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TinyDow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {43 0f b6 04 0e 43 88 04 08 4d 8d 49 01 84 c0 75 ?? 4c 89 64 24 30 45 33 c9 c7 44 24 28 02 00 00 00 45 33 c0 ba 00 00 00 40 c7 44 24 20 02 00 00 00 49 8b cf ff 15 15 16 00 00 48 8b f8 48 8d 45 80 48 ff c3 44 38 24 18 75 ?? 4c 8b c3 4c 89 64 24 20 4c 8d 4c 24 40 48 8b cf 48 8d 55 80 ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = "start /min cmd /c" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

