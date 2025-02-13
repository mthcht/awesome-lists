rule Trojan_MSIL_PowStart_SB_2147900876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PowStart.SB"
        threat_id = "2147900876"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PowStart"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PS2EXE_Host" ascii //weight: 1
        $x_1_2 = "JHN0YXJ0cHJvY2Vzc1BhcmFtcyA9IEB7DQogICAgRmlsZVBhdGggICAgID0gIiRFbnY6U3lzdGVtUm9vdFxSRUdFRElULm" ascii //weight: 1
        $x_1_3 = "V4ZSINCiAgICBBcmd1bWVudExpc3QgPSAnL3MnLCAnQzpcV2luZG93c1xTeXN0ZW0zMlx0ZW1wMS5yZWcnDQogICAgVmVy" ascii //weight: 1
        $x_1_4 = "YiAgICAgICAgID0gJ1J1bkFzJw0KICAgIFBhc3NUaHJ1ICAgICA9ICR0cnVlDQogICAgV2FpdCAgICAgICAgID0gJHRydW" ascii //weight: 1
        $x_1_5 = "UNCn0NCiRwcm9jID0gU3RhcnQtUHJvY2VzcyBAc3RhcnRwcm9jZXNzUGFyYW1z" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

