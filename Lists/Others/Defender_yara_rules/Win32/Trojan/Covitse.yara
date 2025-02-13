rule Trojan_Win32_Covitse_M_2147751691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Covitse.M!MSR"
        threat_id = "2147751691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Covitse"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "dOwNlOaDfIlE('http://81.103.35.44/covid19_truth.jpg', 'C:\\Users\\Public\\covid19_truth.jpg')" ascii //weight: 2
        $x_2_2 = "pOwErShElL -wIn 1 -c C:\\Users\\Public\\covid19_truth.jpg & pOwErShElL -wIn 1 -c \"IEX (NeW-oBjEcT" ascii //weight: 2
        $x_2_3 = "DoWnLoAdStRiNg('http://81.103.35.44/payload.ps1')" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Covitse_AA_2147752155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Covitse.AA!MTB"
        threat_id = "2147752155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Covitse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "source\\repos\\Coronavirus1\\Coronavirus1\\obj\\Debug\\Coronavirus1.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

