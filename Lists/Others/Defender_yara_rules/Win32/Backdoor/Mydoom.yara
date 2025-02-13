rule Backdoor_Win32_Mydoom_2147555595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mydoom"
        threat_id = "2147555595"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mydoom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "fuvztncv.qyy" ascii //weight: 3
        $x_2_2 = "shimgapi.dll" ascii //weight: 2
        $x_3_3 = "Fbsgjner\\Zvpebfbsg\\Jvaqbjf\\PheeragIrefvba\\Rkcybere\\PbzQyt32\\Irefvba" ascii //weight: 3
        $x_2_4 = "zincite" ascii //weight: 2
        $x_3_5 = "VagreargTrgPbaarpgrqFgngr" ascii //weight: 3
        $x_3_6 = "jvavarg.qyy " ascii //weight: 3
        $x_3_7 = "jvanzc5" ascii //weight: 3
        $x_3_8 = "jjj.zvpebfbsg.pbz" ascii //weight: 3
        $x_2_9 = "0.0.0.0 www.microsoft.com" ascii //weight: 2
        $x_3_10 = "KHUDTOC.SDaRXL.MSDBKHUDTOC.SDaBNL" ascii //weight: 3
        $x_2_11 = "VVVaLB.EDDaBNL" ascii //weight: 2
        $x_3_12 = "Fbsgjner\\Xnmnn\\Genafsre" ascii //weight: 3
        $x_3_13 = "Fbsgjner\\Zvpebfbsg\\Jvaqbjf\\PheeragIrefvba\\Eha" ascii //weight: 3
        $x_4_14 = "Fbsgjner\\Zvpebfbsg\\JNO\\JNO4\\Jno Svyr Anzr" ascii //weight: 4
        $x_3_15 = "Fbsgjner\\Zvpebfbsg\\Vagrearg Nppbhag Znantre\\Nppbhagf" ascii //weight: 3
        $x_3_16 = "FZGC Freire" ascii //weight: 3
        $x_1_17 = "SMTP Display Name" ascii //weight: 1
        $x_1_18 = "mx.%s" ascii //weight: 1
        $x_1_19 = "IEFrame" ascii //weight: 1
        $x_1_20 = "ATH_Note" ascii //weight: 1
        $x_2_21 = "rctrl_renwnd32" ascii //weight: 2
        $x_1_22 = "\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_23 = "DnsQuery_A" ascii //weight: 1
        $x_2_24 = "            .pif" ascii //weight: 2
        $x_1_25 = "the attached file for details" ascii //weight: 1
        $x_1_26 = "software\\microsoft\\wab\\wab4\\wab" ascii //weight: 1
        $x_1_27 = "document.zip" ascii //weight: 1
        $x_3_28 = "EPCG GB:<%f>" ascii //weight: 3
        $x_2_29 = "220 Bot Server (Win32)" ascii //weight: 2
        $x_3_30 = "ZNVY SEBZ:<%f>" ascii //weight: 3
        $x_3_31 = "Pbagrag-Qvfcbfvgvba: nggnpuzrag;" ascii //weight: 3
        $x_1_32 = "+++ Attachment: No Virus found" ascii //weight: 1
        $x_2_33 = "http://www.google.com/search?hl=en&ie=UTF-8&oe=UTF-8&q=%s" ascii //weight: 2
        $x_2_34 = "FOR /L %%I IN (1,1,10000) DO c:" ascii //weight: 2
        $x_1_35 = "[-= Smash =-]" ascii //weight: 1
        $x_2_36 = "TS_RND_FROM_DOMAIN" ascii //weight: 2
        $x_2_37 = "TS_SENDER_DOMAIN" ascii //weight: 2
        $x_1_38 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List" ascii //weight: 1
        $x_2_39 = "to netsky's creator(s): imho, skynet" ascii //weight: 2
        $x_2_40 = "c:\\feedlist" ascii //weight: 2
        $x_1_41 = "NetBios Ext" ascii //weight: 1
        $x_2_42 = "Software\\Microsoft\\Office\\Outlook\\OMI Account Manager\\Accounts" ascii //weight: 2
        $x_2_43 = "Software\\Microsoft\\Office\\Outlook\\OMI Accounrosoft\\WAB\\WAB4\\Wab File Name" ascii //weight: 2
        $x_1_44 = "Software\\Microsoft\\Internet Account Manager\\Accounts" ascii //weight: 1
        $x_1_45 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\ICQ.exe" ascii //weight: 1
        $x_2_46 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32" ascii //weight: 2
        $x_1_47 = "RCPT TO:<%s>2" ascii //weight: 1
        $x_3_48 = "tNESV.QD,nHBQNRNES,xHMCNVR,dTQQDMSwDQRHNM,fWOKNQDQ,tGDKKtL.R" ascii //weight: 3
        $x_3_49 = "nDR#VSDKV" ascii //weight: 3
        $x_2_50 = "Mes#wtelw" ascii //weight: 2
        $x_3_51 = "KR.RQUaDWD" ascii //weight: 3
        $x_3_52 = "tNESV.QD,nHBQNRNES,xHMCNVR,dTQQDMSwDQRHNM,sTM" ascii //weight: 3
        $x_3_53 = "tNESV.QD,nHBQNRNES,xHMCNVR ou,dTQQDMSwDQRHNM,xHMKNFNM" ascii //weight: 3
        $x_4_54 = "CQHUDQR,DSB,GNRSRa" ascii //weight: 4
        $x_3_55 = "tNESV.QD,l.Y..,uQ.MREDQ" ascii //weight: 3
        $x_3_56 = "GRDQUaRXR" ascii //weight: 3
        $x_3_57 = "jMSDQMDShDSdNMMDBSDCtS.SD" ascii //weight: 3
        $x_2_58 = "%s, %u %s %u %.2u:%.2u:%.2u %c%.2u%.2u" ascii //weight: 2
        $x_1_59 = "SDE+HOOKLIB Demo" ascii //weight: 1
        $x_1_60 = "*** wsock32.dll::connect/send() api functions are now hooked ***" ascii //weight: 1
        $x_1_61 = "injected_va = 0x%08X = 0x%08X" ascii //weight: 1
        $x_1_62 = "StringTable = 0x%08X = 0x%08X" ascii //weight: 1
        $x_1_63 = "c:\\SOCKEThook.log" ascii //weight: 1
        $x_1_64 = "[x] injected to (%s)" ascii //weight: 1
        $x_2_65 = "[x] done system wide injection" ascii //weight: 2
        $x_2_66 = "H-E-L-L-B-O-T-P-O-L-Y-M-O-R-P-H" ascii //weight: 2
        $x_2_67 = "The source of this worm has been released to public. irc server: irc.powerirc.net #ccpower" ascii //weight: 2
        $x_2_68 = "[x] starting HellBot::v3 beta2" ascii //weight: 2
        $x_3_69 = {2b c2 83 c0 0d 99 b9 1a 00 00 00 f7 f9 8a 44 15}  //weight: 3, accuracy: High
        $x_1_70 = {8b 45 f8 99 b9 3c 00 00 00 f7 f9 52 8b 45 f8 99 b9 3c 00 00 00 f7 f9 50}  //weight: 1, accuracy: High
        $x_1_71 = "Abgvpr: **Ynfg Jneavat**" ascii //weight: 1
        $x_1_72 = "Lbhe rznvy nppbhag" ascii //weight: 1
        $x_1_73 = "Abgvpr:***Lbhe rznvy nppbhag jvyy or fhfcraqrq***" ascii //weight: 1
        $x_1_74 = "Frphevgl zrnfherf" ascii //weight: 1
        $x_1_75 = "Rznvy Nppbhag Fhfcrafvba" ascii //weight: 1
        $x_1_76 = "*VZCBEGNAG*" ascii //weight: 1
        $x_1_77 = "Pbagrag-Glcr:" ascii //weight: 1
        $x_1_78 = "K-Cevbevgl:" ascii //weight: 1
        $x_1_79 = "K-ZFZnvy-Cevbevgl:" ascii //weight: 1
        $x_1_80 = "punefrg=" ascii //weight: 1
        $x_1_81 = "Pbagrag-Genafsre" ascii //weight: 1
        $x_1_82 = "anzr=\"%f\"" ascii //weight: 1
        $x_1_83 = "Pbagrag-Qvfcbfvgvba:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_3_*))) or
            ((1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

