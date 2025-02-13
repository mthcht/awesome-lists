rule Ransom_Python_Dedsec_AA_2147902582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Python/Dedsec.AA!MTB"
        threat_id = "2147902582"
        type = "Ransom"
        platform = "Python: Python scripts"
        family = "Dedsec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 61 6e 73 6f 6d 20 63 6f 70 79 [0-32] 56 43 52 55 4e 54 49 4d 45 31 34 30 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_2 = "PyInstaller: pyi_win32_utils_to_utf8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

