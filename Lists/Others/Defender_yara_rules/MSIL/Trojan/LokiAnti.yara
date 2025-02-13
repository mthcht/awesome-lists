rule Trojan_MSIL_LokiAnti_J_2147743690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiAnti.J!ibt"
        threat_id = "2147743690"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiAnti"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "swety.dll" ascii //weight: 1
        $x_1_2 = {01 11 05 11 0a 74 01 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11}  //weight: 1, accuracy: High
        $x_1_3 = "$06949989-60e7-4a65-b04e-976d74ba907d" ascii //weight: 1
        $x_1_4 = "VirtualMachineDetector" ascii //weight: 1
        $x_1_5 = "STARTUP_INFORMATION" ascii //weight: 1
        $x_1_6 = "PROCESS_INFORMATION" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

