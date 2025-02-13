rule TrojanDropper_O97M_DarkNeuron_A_2147724705_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/DarkNeuron.A!dha"
        threat_id = "2147724705"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "DarkNeuron"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "-----BEGIN CERTIFICATE-----" ascii //weight: 1
        $x_1_2 = {73 20 3d 20 73 20 26 20 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 22}  //weight: 1, accuracy: Low
        $x_1_3 = "-----END CERTIFICATE-----" ascii //weight: 1
        $x_1_4 = "\\\\Signature.crt" ascii //weight: 1
        $x_1_5 = ".Run \"cmd.exe /c certutil -decode \" & " ascii //weight: 1
        $x_1_6 = "\"\\\\Sign.exe\", windowStyle, waitOnReturn" ascii //weight: 1
        $x_1_7 = "=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii //weight: 1
        $x_1_8 = "Function s2() As String" ascii //weight: 1
        $x_1_9 = "Dim windowStyle As Integer: windowStyle = 0" ascii //weight: 1
        $x_1_10 = "Dim waitOnReturn As Boolean: waitOnReturn = True" ascii //weight: 1
        $x_1_11 = "Set wsh = VBA.CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_12 = "Fileout.Write StrReverse(s2() & s)" ascii //weight: 1
        $x_1_13 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

