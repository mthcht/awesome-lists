rule Backdoor_Win32_QakBot_BK_2147729993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/QakBot.BK!MTB"
        threat_id = "2147729993"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bcdfghklmnpqrstvwxz" ascii //weight: 1
        $x_1_2 = "%s?enc&comp=%s&ext=clipboard.txt" ascii //weight: 1
        $x_1_3 = "%s?cstorage=ddos&comp=%s" ascii //weight: 1
        $x_1_4 = "ad6af8bd5835d19cc7fdc4c62fdf02a1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_QakBot_BK_2147729993_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/QakBot.BK!MTB"
        threat_id = "2147729993"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "automaticallyHremoved.Sonusers" wide //weight: 1
        $x_1_2 = "tfOmnibox,thatreportedtheSfirst3" wide //weight: 1
        $x_1_3 = "1ItFeaturesitprofessor5Inplayer" wide //weight: 1
        $x_1_4 = "topgunEconomicwith2015.195So" wide //weight: 1
        $x_1_5 = "bywithEmeanthitsIS" wide //weight: 1
        $x_1_6 = "EhiddenPandi59visitedadministratorX" wide //weight: 1
        $x_1_7 = "Bsupported1maxwellprovider3were8v0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

