rule TrojanDownloader_Win32_Senekil_A_2147577542_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Senekil.gen!A"
        threat_id = "2147577542"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Senekil"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "assistse.exe,kregex.exe,trojdie.kxp,kvsrvxp.exe,kvmonxp.kxp,frogagent.exe,kvxp.kxp,ccenter.exe,ravmond.exe,ravmon.exe,rfwmain.exe,rfwsrv.exe,kpfwsvc.exe,kavpfw.exe,kavstart.exe,kmailmon.exe,kwatch.exe,avp.exe" ascii //weight: 10
        $x_10_2 = "kav.exe,kavsvc.exe,rtvscan.exe,ccsetmgr.exe,defwatch.exe,ccevtmgr.exe,ccapp.exe,mcshield.exe,mcvsescn.exe,mcdetect.exe,mcmnhdlr.exe,trojanwall.exe,fygtcleaner.exe,mantispm.exe,vsmon.exe,isafe.exe,zlclient.exe" ascii //weight: 10
        $x_10_3 = "pcclient.exe,pcctlcom.exe,tmpfw.exe,tmntsrv.exe,tmproxy.exe,pccguide.exe,iparmor.exe,xfilter.exe,filmsg.exe,avengine.exe,pavsrv51.exe,psimsvc.exe,pavprsrv.exe,tpsrv.exe,pavprsrv.exe,apvxdwin.exe,srvload.exe,webproxy.exe" ascii //weight: 10
        $x_10_4 = "KVSrvXP,KVWSC,RsCCenter,RsRavMon,RfwService,KWatchSvc,KPfwSvc,AVP,kavsvc,McTskshd.exe,McDetect.exe,CAISafe,vsmon,Tmntsrv,PcCtlCom,TmPfw,tmproxy,pmshellsrv,PAVSRV,PAVFNSVR,PSIMSVC,PNMSRV,PavPrSrv,TPSrv" ascii //weight: 10
        $x_10_5 = "KVSrvXP,KVWSC,KWatchSvc,KPfwSvc,AVP,kavsvc,RsCCenter,McTskshd.exe,McDetect.exe,CAISafe,vsmon,Tmntsrv,PcCtlCom,TmPfw,tmproxy,pmshellsrv,PAVSRV,PAVFNSVR,PSIMSVC,PNMSRV,PavPrSrv,TPSrv" ascii //weight: 10
        $x_10_6 = "AVP.CloseRequestDialog" ascii //weight: 10
        $x_1_7 = "wSkysoft" ascii //weight: 1
        $x_1_8 = "Jiangmin Registry Monitor Ex" ascii //weight: 1
        $x_1_9 = "KVXP_Monitor" ascii //weight: 1
        $x_1_10 = "KernelCheck" ascii //weight: 1
        $x_1_11 = "Forthgoer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

