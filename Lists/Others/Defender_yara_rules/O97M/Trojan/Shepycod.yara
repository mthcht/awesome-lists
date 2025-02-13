rule Trojan_O97M_Shepycod_A_2147710766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Shepycod.A"
        threat_id = "2147710766"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Shepycod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "90"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Private Sub Workbook_Open()" ascii //weight: 10
        $x_10_2 = "Dim ws As Worksheet" ascii //weight: 10
        $x_10_3 = "Dim oo As OLEObject" ascii //weight: 10
        $x_10_4 = "Set ws = Sheets(\"Sheet3\")" ascii //weight: 10
        $x_10_5 = "Set oo = ws.OLEObjects(\"Object 1\")" ascii //weight: 10
        $x_10_6 = "Set myWS = CreateObject(\"WScript.Shell\")" ascii //weight: 10
        $x_10_7 = "myWS.RegWrite \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3\\1806\", \"0\", \"REG_DWORD\"" ascii //weight: 10
        $x_10_8 = "oo.Verb xlVerbPrimary" ascii //weight: 10
        $x_10_9 = "myWS.RegWrite \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3\\1806\", \"1\", \"REG_DWORD\"" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

