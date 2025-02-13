rule Worm_Win32_DuiskBot_2147597620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/DuiskBot"
        threat_id = "2147597620"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "DuiskBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "e-gold" ascii //weight: 1
        $x_1_2 = "SOCKS4" ascii //weight: 1
        $x_1_3 = "Scanning %s." ascii //weight: 1
        $x_1_4 = "YahooBuddyMain" ascii //weight: 1
        $x_1_5 = "{SNIFFER}:" ascii //weight: 1
        $x_1_6 = "Wells Fargo" ascii //weight: 1
        $x_2_7 = "google.com/url?q=http://%s:%d" ascii //weight: 2
        $x_2_8 = "&del Cookies\\*.txt>NUL" ascii //weight: 2
        $x_2_9 = "%s\\dllcache\\%s" ascii //weight: 2
        $x_2_10 = "*@fbi.gov" ascii //weight: 2
        $x_2_11 = "Exploited" ascii //weight: 2
        $x_2_12 = "IMWindowClass" ascii //weight: 2
        $x_2_13 = "MSNHiddenWindowClass" ascii //weight: 2
        $x_2_14 = {49 45 2d 56 4d 4c 00}  //weight: 2, accuracy: High
        $x_2_15 = ":image><MetaSploit:" ascii //weight: 2
        $x_3_16 = "%d%d%d_vml." ascii //weight: 3
        $x_4_17 = "Spread}: %d" ascii //weight: 4
        $x_4_18 = "net stop \"Norton" ascii //weight: 4
        $x_5_19 = "%u9090%u9090%u9090%uCCE9%u" ascii //weight: 5
        $x_3_20 = "{REVERSE-CMD}:" ascii //weight: 3
        $x_4_21 = "{IMSPREAD}:" ascii //weight: 4
        $x_5_22 = {5b 4e 4d 4c 4b 5d 00 5b 4e 4d 4c 4b 5d 00}  //weight: 5, accuracy: High
        $x_5_23 = {32 4b 00 00 7b 53 59 53 49 4e 46 4f 7d 3a}  //weight: 5, accuracy: High
        $x_5_24 = {6a 70 67 00 69 73 6f 00 6d 70 33 00 70 64 66 00}  //weight: 5, accuracy: High
        $x_5_25 = "UID=%s;PWD=%s;%s" ascii //weight: 5
        $x_5_26 = ":*!*@* * * :*syn" ascii //weight: 5
        $x_5_27 = {3a 25 6c 73 00 00 50 61 73 73 70 6f 72 74 2e 4e}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((6 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((2 of ($x_3_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*))) or
            ((3 of ($x_4_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*))) or
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

