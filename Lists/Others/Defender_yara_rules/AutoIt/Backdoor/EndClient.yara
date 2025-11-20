rule Backdoor_AutoIt_EndClient_A_2147957830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AutoIt/EndClient.A"
        threat_id = "2147957830"
        type = "Backdoor"
        platform = "AutoIt: AutoIT scripts"
        family = "EndClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GOINTOFILEPATH($spath)" ascii //weight: 1
        $x_1_2 = "DOWNLOADPROCESS($isocket," ascii //weight: 1
        $x_1_3 = "WRITEREMOTESHELL($scommand)" ascii //weight: 1
        $x_1_4 = "REMOTESHELLPROCESS($isocket)" ascii //weight: 1
        $x_1_5 = "DELETEFILEORFOLDER($path)" ascii //weight: 1
        $x_1_6 = "\\Smart_Web.lnk" ascii //weight: 1
        $x_1_7 = "Local $batfile = \"C:\\Users\\Public\\Documents\\\" & $batfilename & \".bat\"" ascii //weight: 1
        $x_1_8 = "Local $avastprocesses[0x2]" ascii //weight: 1
        $x_1_9 = "SEND($isocket, \"endClient" ascii //weight: 1
        $x_1_10 = "Global $gsmutex = \"Global\\AB732E15-D8DD-87A1-7464-CE6698819E701\"" ascii //weight: 1
        $x_1_11 = "Global $cmd_upload = \"upload\"" ascii //weight: 1
        $x_1_12 = "Global $uploadpath = @ScriptDir, $uploadfilename = \"1.rar\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

