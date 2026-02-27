rule Trojan_MSIL_Loader_ARR_2147961324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Loader.ARR!MTB"
        threat_id = "2147961324"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Loader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0b 06 18 5d 16 fe 01 0c 08 2c 07}  //weight: 10, accuracy: High
        $x_8_2 = "start.exe" ascii //weight: 8
        $x_2_3 = "frEZpjRb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Loader_AMTB_2147963852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Loader!AMTB"
        threat_id = "2147963852"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Loader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nemesis.exe" ascii //weight: 1
        $x_1_2 = "G:\\nemesis\\nemesis\\obj\\Release\\nemesis.pdb" ascii //weight: 1
        $x_1_3 = "WiFis.txt" ascii //weight: 1
        $x_1_4 = "InstalledApps.txt" ascii //weight: 1
        $x_1_5 = "nemesis_debug.txt" ascii //weight: 1
        $n_100_6 = "Uninst.exe" ascii //weight: -100
        $n_100_7 = "Uninstaller.exe" ascii //weight: -100
        $n_100_8 = "Uninstal.exe" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

