rule Worm_Win32_Wootbot_2147596951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Wootbot"
        threat_id = "2147596951"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Wootbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 02 02 00 00 ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 8e ?? ?? 00 00 e8 ?? ?? ?? ?? 8d 8e ?? ?? 00 00 e8 ?? ?? ?? ?? 8d be ?? ?? 00 00 8b cf e8 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 68 e8 03 00 00 ff d3 8b cf e8 ?? ?? ?? ?? 68 e8 03 00 00 ff d3}  //weight: 1, accuracy: Low
        $x_1_2 = {68 02 02 00 00 ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 81 c1 ?? ?? 00 00 e8 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 81 c1 ?? ?? 00 00 e8 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 81 c1 ?? ?? 00 00 e8 ?? ?? ?? ?? 68 e8 03 00 00 ?? ?? ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 81 c1 ?? ?? 00 00 e8 ?? ?? ?? ?? 68 e8 03 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Worm_Win32_Wootbot_B_2147606619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Wootbot.gen!B"
        threat_id = "2147606619"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Wootbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tftp.exe -i  get" ascii //weight: 1
        $x_1_2 = "forsyn" ascii //weight: 1
        $x_1_3 = "Scan(%s): %s Port Scan %s:%d" ascii //weight: 1
        $x_1_4 = "ftp -n -v -s:" ascii //weight: 1
        $x_1_5 = "[%s] Finished flooding %s %d Times" ascii //weight: 1
        $x_1_6 = {57 6f 6f 74 00}  //weight: 1, accuracy: High
        $x_1_7 = "a|b|c|d|e|f|g|h|i|j|k|l|m|n" ascii //weight: 1
        $x_1_8 = {6a 00 6a 0b 6a 03 6a 09 6a 0e 6a 04 6a 0e 6a 12 6a 4f 8d 54 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

