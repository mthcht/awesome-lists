rule TrojanSpy_Win32_BBSwift_A_2147711139_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/BBSwift.A"
        threat_id = "2147711139"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "BBSwift"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Failed to control printer. cmd=%d, err=%d" ascii //weight: 2
        $x_2_2 = "DELETE FROM SAAOWNER.TEXT_%s WHERE TEXT_S_UMID" ascii //weight: 2
        $x_2_3 = "Failed to enumjobs. err=%d" ascii //weight: 2
        $x_2_4 = "SELECT * FROM (SELECT JRNL_DISPLAY_TEXT, JRNL_DATE_TIME FROM SAAOWNER.JRNL_%s WHERE JRNL_DISPLAY_TEXT" ascii //weight: 2
        $x_1_5 = ":%s:%c%s%.2d%s%s%s" ascii //weight: 1
        $x_1_6 = "CFG OK(%s)" ascii //weight: 1
        $x_1_7 = {46 45 44 45 52 41 4c 20 52 45 53 45 52 56 45 20 42 41 4e 4b 00}  //weight: 1, accuracy: High
        $x_1_8 = "echo exit | \"%s\" -S / as sysdba @%s >" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_BBSwift_B_2147711140_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/BBSwift.B"
        threat_id = "2147711140"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "BBSwift"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4e 52 20 2d 20 43 46 47 20 4f 4b 20 28 25 64 29 00}  //weight: 1, accuracy: High
        $x_1_2 = {72 65 63 61 73 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_3 = "[%02d:%02d:%02d] %s" ascii //weight: 1
        $x_1_4 = {2e 22 20 20 5f 44 4f 5f 4e 4f 54 5f 55 53 45 5f 4d 4d 5f 00}  //weight: 1, accuracy: High
        $x_1_5 = {6f 75 74 67 6f 00}  //weight: 1, accuracy: High
        $x_1_6 = {53 77 69 66 74 20 49 6e 70 75 74 00}  //weight: 1, accuracy: High
        $x_1_7 = {32 38 43 3a 20 53 74 61 74 65 6d 65 6e 74 20 4e 75 6d 62 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

