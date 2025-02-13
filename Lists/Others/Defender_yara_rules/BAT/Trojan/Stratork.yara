rule Trojan_BAT_Stratork_B_2147651246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:BAT/Stratork.B"
        threat_id = "2147651246"
        type = "Trojan"
        platform = "BAT: Basic scripts"
        family = "Stratork"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Run\" /v \"Windows Lives\" /t REG_SZ /d %exe%" ascii //weight: 1
        $x_1_2 = "pac=file://%APPDATA:\\=/%/%COMPUTERNAME%.pac" ascii //weight: 1
        $x_1_3 = "echo \"AutoConfigURL\"=\"%pac%\" >> \"%appdata%\\%USERNAME%.reg" ascii //weight: 1
        $x_1_4 = "copy \"%temp%\\leiame.txt\" \"%appdata%\\%COMPUTERNAME%.pac" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

