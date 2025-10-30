rule Trojan_O97M_MuddyWater_AMTB_2147956379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/MuddyWater!AMTB"
        threat_id = "2147956379"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "MuddyWater"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pathasstringpath=\"c:\\\\users\\\\public\\\\hostmanager.log" ascii //weight: 1
        $x_1_2 = "subpol(filepathasstring)shell\"cmd.exe/c\"\"\"&filepath&\"\"\"\",vbnormalfoc" ascii //weight: 1
        $x_1_3 = "fori=0toubound(bytearray)hexbyte=mid(hexstring,i*2+1,2)bytearray(i)=cbyte(\"&h\"&hexbyte)nexti" ascii //weight: 1
        $x_1_4 = "openpath_2forbinaryaccesswriteas#filenumput#filenum,,binarydataclose#filenum" ascii //weight: 1
        $x_1_5 = "base64string=userform1.textbox1.text" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

