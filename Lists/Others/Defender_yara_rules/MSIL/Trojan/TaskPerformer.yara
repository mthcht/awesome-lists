rule Trojan_MSIL_TaskPerformer_A_2147773978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TaskPerformer.A!dha"
        threat_id = "2147773978"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TaskPerformer"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "887930cf-7a4c-409d-ab2b-97ce8b5d8aeb" ascii //weight: 3
        $x_2_2 = "\\taskperformer_server\\taskperformer\\" ascii //weight: 2
        $x_2_3 = "taskperformer.src." ascii //weight: 2
        $x_1_4 = "7300650063006F006E0064006100720079002E00700068007000" wide //weight: 1
        $x_1_5 = "7000720069006D006100720079005F006D00610069006E002E00700068007000" wide //weight: 1
        $x_1_6 = "select MACAddress, IPEnabled from Win32_NetworkAdapterConfiguration" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

