rule TrojanSpy_Win32_Safenet_A_2147681671_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Safenet.A"
        threat_id = "2147681671"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Safenet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Download From Relay(%s) To Remote(%s)" wide //weight: 1
        $x_1_2 = "/safe/record.php" ascii //weight: 1
        $x_1_3 = "SAFEDISKVIRDLG" wide //weight: 1
        $x_1_4 = "SafeCredential.DAT" wide //weight: 1
        $x_1_5 = "name=\"up_file_path\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

