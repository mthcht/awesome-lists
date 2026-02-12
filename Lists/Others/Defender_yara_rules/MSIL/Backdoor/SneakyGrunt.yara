rule Backdoor_MSIL_SneakyGrunt_A_2147962889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/SneakyGrunt.A!dha"
        threat_id = "2147962889"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SneakyGrunt"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/v3/upload?uuid={0}&index={1}&parent={2}&uploadKey={3}&hash={4}" wide //weight: 1
        $x_1_2 = "{\"name\":\"" wide //weight: 1
        $x_1_3 = "ca.exe" wide //weight: 1
        $x_1_4 = "/delete/permanent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

