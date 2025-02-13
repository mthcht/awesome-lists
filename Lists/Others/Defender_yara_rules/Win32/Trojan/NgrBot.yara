rule Trojan_Win32_NgrBot_MA_2147823226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NgrBot.MA!MTB"
        threat_id = "2147823226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NgrBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? c1 f8 10 25 ff 7f 00 00 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {99 b9 e8 03 00 00 f7 f9 81 c2 f4 01 00 00 0f af d6 52 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 68 01 00 1f 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = "from removing our bot file!" ascii //weight: 1
        $x_1_4 = "Message hijacked!" ascii //weight: 1
        $x_1_5 = "*youporn.*/login*" ascii //weight: 1
        $x_1_6 = "ngrBot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

