rule Ransom_Python_FileCoder_AA_2147907225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Python/FileCoder.AA!MTB"
        threat_id = "2147907225"
        type = "Ransom"
        platform = "Python: Python scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {62 65 73 74 6d 61 6c 77 61 72 65 [0-32] 70 79 69 2d 63 6f 6e 74 65 6e 74 73 2d 64 69 72 65 63 74 6f 72 79}  //weight: 1, accuracy: Low
        $x_1_2 = "email.encoders" ascii //weight: 1
        $x_1_3 = "PyInstaller: pyi_win32_utils_to_utf8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

