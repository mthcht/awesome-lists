rule HackTool_MSIL_Uflooder_A_2147708728_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Uflooder.A!bit"
        threat_id = "2147708728"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Uflooder"
        severity = "High"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UDP_Flood" ascii //weight: 1
        $x_1_2 = "Start Attack" wide //weight: 1
        $x_1_3 = "Eternals UDP Flood" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MSIL_Uflooder_C_2147709445_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Uflooder.C!bit"
        threat_id = "2147709445"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Uflooder"
        severity = "High"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Select a proper attack method" wide //weight: 1
        $x_1_2 = "LOIC.exe" wide //weight: 1
        $x_1_3 = "Low Orbit Ion Cannon" wide //weight: 1
        $x_1_4 = "TCP/IP stress-test tool" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MSIL_Uflooder_D_2147711198_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Uflooder.D!bit"
        threat_id = "2147711198"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Uflooder"
        severity = "High"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TCP flood" wide //weight: 1
        $x_1_2 = "UDP flood" wide //weight: 1
        $x_1_3 = "Stopped all attacks" wide //weight: 1
        $x_1_4 = "Sending Conhold flood" wide //weight: 1
        $x_1_5 = "attacks are currently running" wide //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

