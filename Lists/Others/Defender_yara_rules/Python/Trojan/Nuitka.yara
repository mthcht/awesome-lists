rule Trojan_Python_Nuitka_RR_2147964174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Python/Nuitka.RR!MTB"
        threat_id = "2147964174"
        type = "Trojan"
        platform = "Python: Python scripts"
        family = "Nuitka"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 c9 c1 e8 08 33 04 8a 89 c1 41 32 41 0a 0f b6 c0 c1 e9 08 33 0c 82 89 c8 41 32 49 0b 0f b6 c9 c1 e8 08 33 04 8a}  //weight: 1, accuracy: High
        $x_1_2 = "uqmake.exe" ascii //weight: 1
        $x_1_3 = "LazyLoader.exec_module" ascii //weight: 1
        $x_1_4 = "aNUITKA_PACKAGE_shiboken6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

