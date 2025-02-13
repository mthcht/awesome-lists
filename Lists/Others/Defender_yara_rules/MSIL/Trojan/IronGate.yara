rule Trojan_MSIL_IronGate_A_2147712341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/IronGate.A"
        threat_id = "2147712341"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "IronGate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\Users\\Main\\Desktop\\Step7ProSimProxy\\Step7ProSimProxy\\obj\\Release\\Step7ProSim.pdb" ascii //weight: 1
        $x_1_2 = "$863d8af0-cee6-4676-96ad-13e8540f4d47" ascii //weight: 1
        $x_1_3 = "<FindFileInDrive>b__3" ascii //weight: 1
        $x_1_4 = "biogas.exe" wide //weight: 1
        $x_1_5 = "Killing relevant processes..." wide //weight: 1
        $x_1_6 = "$ccc64bc5-ef95-4217-adc4-5bf0d448c272" ascii //weight: 1
        $x_1_7 = "c:\\Users\\Main\\Desktop\\PackagingModule\\PackagingModule\\obj\\Release\\PackagingModule.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

