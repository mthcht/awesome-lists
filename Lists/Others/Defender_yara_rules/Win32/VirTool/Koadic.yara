rule VirTool_Win32_Koadic_A_2147732039_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Koadic.A"
        threat_id = "2147732039"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Koadic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=new ActiveXObject(\"WScript.Shell\");" ascii //weight: 1
        $x_2_2 = "=\"999999999999999\";" ascii //weight: 2
        $x_1_3 = "(\"ping 127.0.0.1 -n 2\",false);}}}" ascii //weight: 1
        $x_1_4 = "=\"Select * From Win32_Process\"" ascii //weight: 1
        $x_1_5 = "()+\".txt\";" ascii //weight: 1
        $x_1_6 = ".run(\"certutil -encodehex \"" ascii //weight: 1
        $x_1_7 = ".Get(\"Win32_Process\")" ascii //weight: 1
        $x_1_8 = "201,stream.Size);" ascii //weight: 1
        $x_1_9 = ".open('','_self','')" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Koadic_A_2147732039_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Koadic.A"
        threat_id = "2147732039"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Koadic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=new ActiveXObject(\"WScript.Shell\");" ascii //weight: 1
        $x_1_2 = "=\"stage\"" ascii //weight: 1
        $x_1_3 = "?sid=" ascii //weight: 1
        $x_1_4 = ";csrf=" ascii //weight: 1
        $x_1_5 = "+net.ComputerName;" ascii //weight: 1
        $x_1_6 = "(\"ping 127.0.0.1 -n 2\",false);}}}" ascii //weight: 1
        $x_1_7 = ".Run(cmd,0,!fork);}" ascii //weight: 1
        $x_1_8 = "()+\".txt\")" ascii //weight: 1
        $x_1_9 = "+osbuild;}" ascii //weight: 1
        $x_1_10 = "\\\\..\\\\..\\\\..\\\\mshtml,RunHTMLApplication\"" ascii //weight: 1
        $x_1_11 = "scrobj.dll\";if(fork32Bit)" ascii //weight: 1
        $x_1_12 = "rundll32.exe javascript:\\\"\\\\..\\\\mshtml," ascii //weight: 1
        $x_1_13 = "\"wmic os get /FORMAT:\\" ascii //weight: 1
        $x_2_14 = "=\"999999999999999\";" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Koadic_A_2147732039_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Koadic.A"
        threat_id = "2147732039"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Koadic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "=new ActiveXObject(\"WScrip" ascii //weight: 1
        $x_1_2 = {28 00 22 00 70 00 69 00 6e 00 67 00 20 00 [0-32] 20 00 2d 00 6e 00 20 00 32 00 22 00 2c 00 66 00 61 00 6c 00 73 00 65 00 29 00 3b 00 7d 00 7d 00 7d 00}  //weight: 1, accuracy: Low
        $x_1_3 = {28 22 70 69 6e 67 20 [0-32] 20 2d 6e 20 32 22 2c 66 61 6c 73 65 29 3b 7d 7d 7d}  //weight: 1, accuracy: Low
        $x_1_4 = {22 00 63 00 65 00 72 00 74 00 [0-32] 20 00 2d 00 65 00 6e 00 63 00 6f 00 64 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = {22 63 65 72 74 [0-32] 20 2d 65 6e 63 6f 64 65}  //weight: 1, accuracy: Low
        $x_1_6 = {2e 00 52 00 75 00 6e 00 28 00 63 00 6d 00 64 00 2c 00 [0-16] 2c 00 21 00 66 00 6f 00 72 00 6b 00 29 00 3b 00 7d 00}  //weight: 1, accuracy: Low
        $x_1_7 = {2e 52 75 6e 28 63 6d 64 2c [0-16] 2c 21 66 6f 72 6b 29 3b 7d}  //weight: 1, accuracy: Low
        $x_1_8 = "mshtml," ascii //weight: 1
        $x_1_9 = ".UserDomain.length!=0" ascii //weight: 1
        $x_1_10 = "=\"stage\"" ascii //weight: 1
        $x_1_11 = "()+\".txt\"" ascii //weight: 1
        $x_1_12 = ".Get(\"Win32_Process\")" ascii //weight: 1
        $x_1_13 = "jobkey,work.status==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule VirTool_Win32_Koadic_A_2147732039_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Koadic.A"
        threat_id = "2147732039"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Koadic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ActiveXObject(\"WScript.Shell\"),STAGER:\"http" ascii //weight: 1
        $x_1_2 = "?sid=" ascii //weight: 1
        $x_1_3 = ";csrf=" ascii //weight: 1
        $x_1_4 = ".isHTA=function()" ascii //weight: 1
        $x_1_5 = ".uuid()+\".txt\")" ascii //weight: 1
        $x_1_6 = "+net.ComputerName;" ascii //weight: 1
        $x_1_7 = ".user.shellchcp();" ascii //weight: 1
        $x_1_8 = "\\\\..\\\\..\\\\..\\\\mshtml,RunHTMLApplication\"" ascii //weight: 1
        $x_1_9 = ".shell.run(\"ping 127.0.0.1 -n 2" ascii //weight: 1
        $x_1_10 = ".WS.Run(cmd,0,!fork);}" ascii //weight: 1
        $x_1_11 = "scrobj.dll\";if(fork32Bit)" ascii //weight: 1
        $x_1_12 = "rundll32.exe javascript:\\\"\\\\..\\\\mshtml," ascii //weight: 1
        $x_1_13 = "\"wmic os get /FORMAT:\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

