rule Backdoor_Win32_Mirai_A_2147719921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mirai.A"
        threat_id = "2147719921"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mirai"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {74 1d 8d 48 ff 8a 40 ff 84 c0 74 0a 3c ff 74 06 fe c8 88 01 eb 09 51 e8}  //weight: 2, accuracy: High
        $x_1_2 = "/ver.txt" ascii //weight: 1
        $x_1_3 = "/update.txt" ascii //weight: 1
        $x_1_4 = "http://%s:8888/" ascii //weight: 1
        $x_1_5 = "\\msinfo.exe" ascii //weight: 1
        $x_1_6 = "/delete /f /tn msinfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Mirai_A_2147722027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mirai.gen!A"
        threat_id = "2147722027"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mirai"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "'sc config SQLSERVERAGENT start= auto'" ascii //weight: 1
        $x_1_2 = "//%s:8888/ups.rar" ascii //weight: 1
        $x_1_3 = "//%s:8888/wpd.dat" ascii //weight: 1
        $x_1_4 = "//%s:8888/wpdmd5.txt" ascii //weight: 1
        $x_1_5 = "//down2.b5w91.com:8443" ascii //weight: 1
        $x_1_6 = "/shell?%s" ascii //weight: 1
        $x_1_7 = ";Drop Procedure sp_password;" ascii //weight: 1
        $x_1_8 = ";exec sp_add_jobserver" ascii //weight: 1
        $x_1_9 = ";EXEC sp_droplogin" ascii //weight: 1
        $x_1_10 = ";exec(@a);" ascii //weight: 1
        $x_1_11 = "<sip:carol@chicago.com>" ascii //weight: 1
        $x_1_12 = "@name='bat.exe',@freq_type=4,@active_start_date" ascii //weight: 1
        $x_1_13 = "@shell INT EXEC SP_" ascii //weight: 1
        $x_1_14 = "[Cracker:CCTV]" ascii //weight: 1
        $x_1_15 = "[Cracker:MSSQL]" ascii //weight: 1
        $x_1_16 = "[Cracker:MSSQL] Host:%s, blindExec CMD: %s" ascii //weight: 1
        $x_1_17 = "[Cracker:RDP]" ascii //weight: 1
        $x_1_18 = "[Cracker:Telnet]" ascii //weight: 1
        $x_1_19 = "[Cracker]" ascii //weight: 1
        $x_1_20 = "[cService]" ascii //weight: 1
        $x_1_21 = "[ExecCode]" ascii //weight: 1
        $x_2_22 = "[ExecCode]AUTHORIZATION [dbo] FROM 0x4D5A" ascii //weight: 2
        $x_1_23 = "[IpFetcher]" ascii //weight: 1
        $x_1_24 = "[Logger_Stdout]" ascii //weight: 1
        $x_1_25 = "[Scanner]" ascii //weight: 1
        $x_1_26 = "[ServerAgent]" ascii //weight: 1
        $x_1_27 = "[SqlStoredProcedure1]" ascii //weight: 1
        $x_1_28 = "[StoredProcedures]" ascii //weight: 1
        $x_1_29 = "[TP:%s]" ascii //weight: 1
        $x_1_30 = "[TP:%s] %d threads created" ascii //weight: 1
        $x_1_31 = "[UpdateThread:]" ascii //weight: 1
        $x_1_32 = "\\Run','rundll32';" ascii //weight: 1
        $x_1_33 = {00 78 57 69 6e 57 70 64 53 72 76 00}  //weight: 1, accuracy: High
        $x_1_34 = "C:\\Progra~1\\kugou2010&attrib" ascii //weight: 1
        $x_1_35 = "C:\\Progra~1\\mainsoft&attrib" ascii //weight: 1
        $x_1_36 = "C:\\Progra~1\\shengda&attrib" ascii //weight: 1
        $x_1_37 = "cmd3:[%s]" ascii //weight: 1
        $x_1_38 = "CrackerWMI" ascii //weight: 1
        $x_1_39 = "crazy exception!!!" ascii //weight: 1
        $x_1_40 = "dbcc addextendedproc ('sp_" ascii //weight: 1
        $x_1_41 = "dbcc addextendedproc ('xp_" ascii //weight: 1
        $x_1_42 = "declare @a varchar(8000);set @a=0x" ascii //weight: 1
        $x_1_43 = "DEMAND_ACTIVE(id=0x%x)" ascii //weight: 1
        $x_1_44 = "DRIVER={SQL Server}" ascii //weight: 1
        $x_1_45 = "DROP ASSEMBLY ExecCode" ascii //weight: 1
        $x_1_46 = "Drop Procedure sp_" ascii //weight: 1
        $x_1_47 = "Drop Procedure xp_" ascii //weight: 1
        $x_1_48 = "echo -ne '%s' %s upnp; /bin/busybox ECCHI" ascii //weight: 1
        $x_1_49 = "is_srvrolemember(@rolename)" ascii //weight: 1
        $x_1_50 = "MEMBLT(op=0x%x,x=%d,y=%d,cx=%d,cy=%d,id=%d,idx=%d)" ascii //weight: 1
        $x_2_51 = {00 4d 49 52 41 49 00}  //weight: 2, accuracy: High
        $x_1_52 = "rm %s/.t; rm %s/.sh; rm %s/.human" ascii //weight: 1
        $x_1_53 = "sc1 stop sharedaccess&sc stop 1MpsSvc&sc config 1MpsSvc start=" ascii //weight: 1
        $x_1_54 = "Task_Crack_Telnet::infect" ascii //weight: 1
        $x_2_55 = "timeout,the remote server %s dosen't respond!" ascii //weight: 2
        $x_1_56 = "UPLOAD_WGET" ascii //weight: 1
        $x_1_57 = "use msdb;exec sp_add_job '" ascii //weight: 1
        $x_1_58 = "xp_cmdshell" ascii //weight: 1
        $x_1_59 = "};PWD={" ascii //weight: 1
        $x_1_60 = {73 65 74 79 ?? ?? ?? 62 64 65 74}  //weight: 1, accuracy: Low
        $x_1_61 = {75 65 73 70 ?? ?? ?? 65 6d 6f 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

