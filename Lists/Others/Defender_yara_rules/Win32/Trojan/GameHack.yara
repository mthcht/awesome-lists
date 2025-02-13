rule Trojan_Win32_GameHack_A_2147641879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GameHack.A"
        threat_id = "2147641879"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GameHack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".hygame8888.cn" ascii //weight: 1
        $x_1_2 = "/c8c_ini/startup." ascii //weight: 1
        $x_1_3 = "\\drivers\\etc\\service3.ini" ascii //weight: 1
        $x_1_4 = "\\startup1.exe" ascii //weight: 1
        $x_1_5 = "/ExeIni/c8cConfig2_run.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GameHack_H_2147662155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GameHack.H"
        threat_id = "2147662155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GameHack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Credit:= [Bepe] tinggalenter" wide //weight: 1
        $x_1_2 = "iiiiii.dll" wide //weight: 1
        $x_1_3 = "++ E991 ++" wide //weight: 1
        $x_1_4 = "/adfoc.us/" wide //weight: 1
        $x_1_5 = "linkbucks.com" wide //weight: 1
        $x_1_6 = "/toyibg.blogspot.com" wide //weight: 1
        $x_1_7 = "PointBlank.exe" wide //weight: 1
        $x_1_8 = "HSUpdate.exe" wide //weight: 1
        $x_1_9 = "xtrap\\cmdx4.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_GameHack_DHN_2147795228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GameHack.DHN!MTB"
        threat_id = "2147795228"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GameHack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "D:\\All ProJect\\INJECT BCZ EDIT NEW\\Release\\BCZINJECTNEW.pdb" ascii //weight: 1
        $x_1_2 = {32 c1 41 88 44 15 [0-4] 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 42 83 fa ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GameHack_AB_2147896081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GameHack.AB!MTB"
        threat_id = "2147896081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GameHack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "@Steam.exe" ascii //weight: 3
        $x_3_2 = "steamwebhelper.exe" ascii //weight: 3
        $x_3_3 = "Software\\Valve\\Steam" ascii //weight: 3
        $x_3_4 = "VAC Bypass" ascii //weight: 3
        $x_3_5 = "Bypass malfunction detected!" ascii //weight: 3
        $x_3_6 = "Steam will close..." ascii //weight: 3
        $x_3_7 = "steamui.dll" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

