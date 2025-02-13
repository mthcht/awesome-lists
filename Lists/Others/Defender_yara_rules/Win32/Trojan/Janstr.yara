rule Trojan_Win32_Janstr_A_2147630201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Janstr.gen!A"
        threat_id = "2147630201"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Janstr"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "104"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {53 8b d8 8b 83 04 03 00 00 8b 10 ff 92 e0 00 00 00 b2 01 8b 83 10 03 00 00 e8 ?? ?? ?? ?? 5b c3}  //weight: 100, accuracy: Low
        $x_1_2 = "\\webmal.exttt" ascii //weight: 1
        $x_1_3 = "kimecek.asp" ascii //weight: 1
        $x_1_4 = "http://www.ajanster.com/zuppe/" ascii //weight: 1
        $x_1_5 = {2b 25 a3 a3 23 24 bd 7b 7b 3f 3d 29 5f 3f 3d 00}  //weight: 1, accuracy: High
        $x_1_6 = "maillistcek.asp" ascii //weight: 1
        $x_1_7 = "\\prohata" ascii //weight: 1
        $x_1_8 = "webmailgonder2" ascii //weight: 1
        $x_1_9 = "msngiris" ascii //weight: 1
        $x_1_10 = "IdAntiFreeze1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

