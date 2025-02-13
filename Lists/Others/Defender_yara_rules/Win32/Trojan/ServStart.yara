rule Trojan_Win32_ServStart_C_2147642066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ServStart.C"
        threat_id = "2147642066"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ServStart"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 c0 03 33 d2 0f af c6 f7 74 24}  //weight: 2, accuracy: High
        $x_2_2 = {5c a1 b8 bf aa ca bc a1 b9 b2 cb b5 a5 5c b3 cc d0 f2 5c c6 f4 b6 af 5c}  //weight: 2, accuracy: High
        $x_1_3 = "Referer: http://%s:80/http://%s" ascii //weight: 1
        $x_1_4 = "%c%c%c%c%c.exe" ascii //weight: 1
        $x_1_5 = ":\\windows.BAK" ascii //weight: 1
        $x_1_6 = "Host: %s:%d" ascii //weight: 1
        $x_1_7 = "#0%s!" ascii //weight: 1
        $x_1_8 = "wenhuxiu" ascii //weight: 1
        $x_1_9 = "SeShutdownPrivilege" ascii //weight: 1
        $x_1_10 = "\\svchcst.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

