rule Backdoor_MSIL_DriveGraft_C_2147936012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DriveGraft.C!dha"
        threat_id = "2147936012"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DriveGraft"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{{ subject = {0}, importance = {1}, body = {2} }}" wide //weight: 1
        $x_1_2 = "{{ contentType = {0}, content = {1} }}" wide //weight: 1
        $x_1_3 = "{0}\"{1}\"{2}&top=1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

