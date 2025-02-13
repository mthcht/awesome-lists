rule TrojanSpy_Win32_Carriso_A_2147722501_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Carriso.A!bit"
        threat_id = "2147722501"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Carriso"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "http://192.168.11.40/c/t.php" ascii //weight: 2
        $x_1_2 = "FileExecutionModel::ExecuteFileFromBase64Data" ascii //weight: 1
        $x_1_3 = {49 6e 6a 65 63 74 20 4d 61 6e 61 67 65 72 20 44 6f 6e 65 2e [0-32] 43 61 72 72 69 65 72 20 4d 6f 64 75 6c 65}  //weight: 1, accuracy: Low
        $x_1_4 = {43 68 65 63 6b [0-4] 57 69 6e 33 32 [0-4] 50 6c 75 67 69 6e [0-4] 53 65 72 76 65 72 [0-4] 43 6c 6f 75 64 [0-4] 4f 72 61 63 6c 65 [0-4] 4e 56 49 44 49 41 [0-4] 41 75 64 69 6f [0-4] 41 76 69 72 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

