rule Trojan_Win32_Chopper_A_2147694607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chopper.A"
        threat_id = "2147694607"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chopper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 43 68 6f 70 70 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = "<O>act=login</O>" ascii //weight: 1
        $x_1_3 = "Response.WriteFile(Request.Item[\"z1\"]);" wide //weight: 1
        $x_1_4 = "X=CreateObject(\"wscript.shell\").exec(\"\"\"\"&bd(Request(\"z1\"))&\"\"\" /c \"\"\"&bd(Request(\"z2\"))&\"\"\"\"):" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Chopper_SBR_2147760703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chopper.SBR!MSR"
        threat_id = "2147760703"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chopper"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://www.maicaidao.com" wide //weight: 5
        $x_3_2 = "Chopper File" wide //weight: 3
        $x_1_3 = "Driver={Microsoft Access Driver (*.mdb)};DBQ=%s\\cache.tmp;Exclusive=1;pwd" wide //weight: 1
        $x_1_4 = "Provider=Microsoft.Jet.OLEDB.4.0;data source=%s\\cache.tmp;Jet OLEDB:Database Password" wide //weight: 1
        $x_1_5 = "SELECT TOP 1 [Item],[Dat] FROM [CACHE] WHERE [Item]" wide //weight: 1
        $x_1_6 = "Execute(\"Server.ScriptTimeout" wide //weight: 1
        $x_1_7 = "Driver={MySQL};Server=localhost;database=mysql;UID=root;PWD=" wide //weight: 1
        $x_1_8 = "dirname($_SERVER[\"SCRIPT_FILENAME\"])" wide //weight: 1
        $x_1_9 = "EXEC master..xp_cmdshell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

