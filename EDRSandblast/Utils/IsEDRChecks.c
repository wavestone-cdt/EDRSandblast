#include "../EDRSandblast.h"
#include "IsEDRChecks.h"

/*
* Primitives to check if a binary or driver belongs to an EDR product.
*/

// List of keywords matching EDR companies as employed for binary digitial signatures.
// TODO : enrich this list
TCHAR const* EDR_SIGNATURE_KEYWORDS[] = {
   _T("CarbonBlack"),
   _T("CrowdStrike"),
   _T("Cylance Smart Antivirus"),
   _T("Elastic Endpoint Security"),
   _T("FireEye"),
   _T("Kaspersky"),
   _T("McAfee"),
   _T("SentinelOne"),
   _T("Sentinel Labs"),
   _T("Symantec")
};

// List of binaries belonging to EDR products.
TCHAR const* EDR_BINARIES[] = {
    // Microsoft
   _T("HealthService.exe"),
   _T("MonitoringHost.exe"),
   _T("MpCmdRun.exe"),
   _T("MsMpEng.exe"),
   _T("MsSense.exe"),
   _T("SenseCncProxy.exe"),
   _T("SenseIR.exe"),
   // SentinelOne
   _T("LogCollector.exe"),
   _T("SentinelAgent.exe"),
   _T("SentinelAgentWorker.exe"),
   _T("SentinelBrowserNativeHost.exe"),
   _T("SentinelHelperService.exe"),
   _T("SentinelMemoryScanner.exe"),
   _T("SentinelRanger.exe"),
   _T("SentinelRemediation.exe"),
   _T("SentinelRemoteShellHost.exe"),
   _T("SentinelScanFromContextMenu.exe"),
   _T("SentinelServiceHost"),
   _T("SentinelStaticEngine.exe"),
   _T("SentinelStaticEngineScanner.exe"),
   _T("SentinelUI.exe"),
};

// List of EDR drivers for which Kernel callbacks will be impacted.
// Source: https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes
// Includes all FSFilter Anti-Virus and Activity Monitor drivers.
// and : https://github.com/SadProcessor/SomeStuff/blob/master/Invoke-EDRCheck.ps1
TCHAR const* EDR_DRIVERS[] = {
    /*
    * FSFilter Anti-Virus - BEGIN
    */
    // 360 Software (Beijing)
   _T("360qpesv.sys"),
   // 5nine Software Inc.
   _T("5nine.cbt.sys"),
   // Ahkun Co.
   _T("AhkSvPro.sys"),
   _T("AhkUsbFW.sys"),
   _T("AhkAMFlt.sys"),
   // Ahnlab
   _T("V3MifiNt.sys"),
   _T("V3Ift2k.sys"),
   _T("V3IftmNt.sys"),
   _T("ArfMonNt.sys"),
   _T("AhnRghLh.sys"),
   _T("AszFltNt.sys"),
   _T("OMFltLh.sys"),
   _T("V3Flu2k.sys"),
   _T("AdcVcsNT.sys"),
   // AhnLab Inc.
   _T("TfFregNt.sys"),
   // AhnLab, Inc.
   _T("SMDrvNt.sys"),
   _T("ATamptNt.sys"),
   _T("V3Flt2k.sys"),
   // Alwil
   _T("aswmonflt.sys"),
   // Anvisoft
   _T("avfsmn.sys"),
   // Arcdo
   _T("ANVfsm.sys"),
   _T("CDrRSFlt.sys"),
   // Ashampoo GmbH & Co. KG
   _T("AshAvScan.sys"),
   // Australian Projects
   _T("ZxFsFilt.sys"),
   // Authentium
   _T("avmf.sys"),
   // AVG Grisoft
   _T("avgmfx86.sys"),
   _T("avgmfx64.sys"),
   _T("avgmfi64.sys"),
   _T("avgmfrs.sys"),
   // Avira GmbH
   _T("avgntflt.sys"),
   // AVNOS
   _T("kavnsi.sys"),
   // AvSoft Technologies
   _T("strapvista.sys"),
   _T("strapvista64.sys"),
   // AxBx
   _T("vk_fsf.sys"),
   // Baidu (beijing)
   _T("BDFileDefend.sys"),
   // Baidu (Hong Kong) Limited
   _T("Bfilter.sys"),
   // Baidu online network technology (beijing)Co.
   _T("BDsdKit.sys"),
   _T("bd0003.sys"),
   // Beijing Kingsoft
   _T("ksfsflt.sys"),
   // Beijing Majorsec
   _T("majoradvapi.sys"),
   // Beijing Rising Information Technology Corporation Limited
   _T("HookSys.sys"),
   // Beijing Venus
   _T("TxFileFilter.sys"),
   _T("VTSysFlt.sys"),
   // Binary Defense Systems
   _T("Osiris.sys"),
   // Bit9 Inc
   _T("b9kernel.sys"),
   // Bitdefender
   _T("bdsvm.sys"),
   // BitDefender SRL
   _T("hbflt.sys"),
   _T("vlflt.sys"),
   _T("gzflt.sys"),
   _T("bddevflt.sys"),
   _T("ignis.sys"),
   _T("AVCKF.SYS"),
   _T("gemma.sys"),
   _T("Atc.sys"),
   _T("AVC3.SYS"),
   _T("TRUFOS.SYS"),
   // Bkav Corporation
   _T("BkavAutoFlt.sys"),
   _T("BkavSdFlt.sys"),
   // BLACKFORT SECURITY
   _T("bSyirmf.sys"),
   _T("bSysp.sys"),
   _T("bSydf.sys"),
   _T("bSywl.sys"),
   _T("bSyrtm.sys"),
   _T("bSyaed.sys"),
   _T("bSyar.sys"),
   // BullGuard
   _T("BdFileSpy.sys"),
   // C-NetMedia Inc
   _T("antispyfilter.sys"),
   // CheckMAL Inc
   _T("AppCheckD.sys"),
   // Cheetah Mobile Inc.
   _T("wdocsafe.sys"),
   _T("lbprotect.sys"),
   // Cisco Systems
   _T("csaav.sys"),
   _T("CiscoSAM.sys"),
   _T("immunetselfprotect.sys"),
   _T("immunetprotect.sys"),
   _T("CiscoAMPCEFWDriver.sys"),
   _T("CiscoAMPHeurDriver.sys"),
   // CJSC Returnil Software
   _T("rvsmon.sys"),
   // CodeProof Technologies Inc
   _T("CpAvFilter.sys"),
   _T("CpAvKernel.sys"),
   // Comodo Group Inc.
   _T("cmdccav.sys"),
   _T("cmdguard.sys"),
   // Computer Assoc
   _T("caavFltr.sys"),
   _T("ino_fltr.sys"),
   // ConeSecurity Inc
   _T("CSFlt.sys"),
   // Confluera Inc
   _T("tbmninifilter.sys"),
   // Coranti Inc.
   _T("crnsysm.sys"),
   _T("crncache32.sys"),
   _T("crncache64.sys"),
   // CoreTrace Corporation
   _T("bouncer.sys"),
   // CrowdStrike Ltd.
   _T("csagent.sys"),
   // Dakota State University
   _T("EdnemFsFilter.sys"),
   // Deep Instinct
   _T("DeepInsFS.sys"),
   // Deep Instinct Ltd.
   _T("DeepInsFS.sys"),
   // Digitalonnet
   _T("ADSpiderDoc.sys"),
   // Doctor Web
   _T("drwebfwft.sys"),
   _T("DwShield.sys"),
   _T("DwShield64.sys"),
   _T("dwprot.sys"),
   // Doctor Web Ltd.
   _T("Spiderg3.sys"),
   // DriveSentry Inc
   _T("drivesentryfilterdriver2lite.sys"),
   // EasyAntiCheat Solutions
   _T("easyanticheat.sys"),
   // eEye Digital Security
   _T("eeyehv.sys"),
   _T("eeyehv64.sys"),
   // Egnyte Inc
   _T("egnfsflt.sys"),
   // EMC
   _T("ECATDriver.sys"),
   // Emsi Software GmbH
   _T("a2ertpx86.sys"),
   _T("a2ertpx64.sys"),
   _T("a2gffx86.sys"),
   _T("a2gffx64.sys"),
   _T("a2gffi64.sys"),
   _T("a2acc.sys"),
   _T("a2acc64.sys"),
   // EnigmaSoft
   _T("EnigmaFileMonDriver.sys"),
   // ESET, spol. s r.o.
   _T("eamonm.sys"),
   // ESTsecurity Corp
   _T("RSRtw.sys"),
   _T("RSPCRtw.sys"),
   // ESTsoft
   _T("AYFilter.sys"),
   _T("Rtw.sys"),
   // ESTsoft corp.
   _T("EstRkmon.sys"),
   _T("EstRkr.sys"),
   // ETRI
   _T("vrSDetri.sys"),
   _T("vrSDetrix.sys"),
   // Everyzone
   _T("TvMFltr.sys"),
   // EveryZone Inc.
   _T("IProtect.sys"),
   // EveryZone INC.
   _T("TvFiltr.sys"),
   _T("TvDriver.sys"),
   _T("TvSPFltr.sys"),
   _T("TvPtFile.sys"),
   // f-protect
   _T("fpav_rtp.sys"),
   // f-secure
   _T("fsgk.sys"),
   // Filseclab
   _T("fildds.sys"),
   // Fortinet Inc.
   _T("FortiAptFilter.sys"),
   _T("fortimon2.sys"),
   _T("fortirmon.sys"),
   _T("fortishield.sys"),
   // Fujitsu Social Science
   _T("wscm.sys"),
   // FXSEC LTD
   _T("pfkrnl.sys"),
   // G Data
   _T("HookCentre.sys"),
   _T("PktIcpt.sys"),
   _T("MiniIcpt.sys"),
   // GAS Tecnologia
   _T("GbpKm.sys"),
   // Greatsoft Corp.Ltd
   _T("vcdriv.sys"),
   _T("vcreg.sys"),
   _T("vchle.sys"),
   // GRGBanking Equipment
   _T("SECOne_USB.sys"),
   _T("SECOne_Proc10.sys"),
   _T("SECOne_REG10.sys"),
   _T("SECOne_FileMon10.sys"),
   // GridinSoft LLC
   _T("gtkdrv.sys"),
   // HAURI
   _T("VrARnFlt.sys"),
   _T("VrBBDFlt.sys"),
   _T("vrSDfmx.sys"),
   _T("vrSDam.sys"),
   _T("VrAptDef.sys"),
   _T("VrSdCore.sys"),
   _T("VrFsFtM.sys"),
   _T("VrFsFtMX.sys(AMD64)"),
   _T("vradfil2.sys"),
   // HAURI Inc.
   _T("VRAPTFLT.sys"),
   // Hidden Reflex
   _T("epicFilter.sys"),
   // Hitachi Solutions
   _T("hsmltwhl.sys"),
   _T("hssfwhl.sys"),
   // HSM IT-Services Gmbh
   _T("oavfm.sys"),
   // Huorong Security
   _T("sysdiag.sys"),
   // IBM
   _T("issregistry.sys"),
   // IKARUS Security
   _T("ntguard.sys"),
   // Imperva Inc.
   _T("mfdriver.sys"),
   // INCA Internet Co.
   _T("npxgd.sys"),
   _T("npxgd64.sys"),
   _T("tkpl2k.sys"),
   _T("tkpl2k64.sys"),
   _T("GKFF.sys"),
   _T("GKFF64.sys"),
   _T("tkdac2k.sys"),
   _T("tkdacxp.sys"),
   _T("tkdacxp64.sys"),
   _T("tksp2k.sys"),
   _T("tkspxp.sys"),
   _T("tkspxp64.sys"),
   // INCA Internet Co., Ltd
   _T("tkfsft.sys"),
   _T("tkfsft64.sys"),
   _T("tkfsavxp.sys"),
   _T("tkfsavxp64.sys"),
   // Individual developer (Soft3304)
   _T("AntiLeakFilter.sys"),
   // IObit Information Tech
   _T("IMFFilter.sys"),
   // ISS
   _T("issfltr.sys"),
   // K7 Computing Private Ltd.
   _T("K7Sentry.sys"),
   // Kaspersky
   _T("klbg.sys"),
   _T("kldback.sys"),
   _T("kldlinf.sys"),
   _T("kldtool.sys"),
   _T("klif.sys"),
   // Kaspersky Lab
   _T("klam.sys"),
   _T("klif.sys"),
   // KINGSOFT
   _T("dgsafe.sys"),
   // knowwheresoft Ltd
   _T("securoFSD_x64.sys"),
   // Komoku Inc.
   _T("kmkuflt.sys"),
   // Lavasoft AB
   _T("lbd.sys"),
   // Leith Bade
   _T("cwdriver.sys"),
   // Lenovo
   _T("lnvscenter.sys"),
   // Lightspeed Systems Inc.
   _T("SAFsFilter.sys"),
   // Malwarebytes Corp.
   _T("FlightRecorder.sys"),
   _T("mbam.sys"),
   // MastedCode Ltd
   _T("fsfilter.sys"),
   // Max Secure Software
   _T("MaxProc64.sys"),
   _T("MaxProtector.sys"),
   _T("maxcryptmon.sys"),
   _T("SDActMon.sys"),
   // McAfee Inc.
   _T("epdrv.sys"),
   _T("mfencoas.sys"),
   _T("mfehidk.sys"),
   _T("swin.sys"),
   // Meidensha Corp
   _T("WhiteShield.sys"),
   // Microsoft
   _T("WdFilter.sys"),
   _T("mpFilter.sys"),
   _T("SysmonDrv.sys"),
   // MicroWorld Software Services Pvt. Ltd.
   _T("mwfsmfltr.sys"),
   // NeoAutus
   _T("NeoKerbyFilter"),
   // Netlor SAS
   _T("KUBWKSP.sys"),
   // NetSecurity Corp
   _T("trfsfilter.sys"),
   // NHN
   _T("nsminflt.sys"),
   _T("nsminflt64.sys"),
   // Norman
   _T("nvcmflt.sys"),
   // Norman ASA
   _T("nprosec.sys"),
   _T("nregsec.sys"),
   // Novatix Corporation
   _T("NxFsMon.sys"),
   // NPcore Ltd
   _T("FileScan.sys"),
   // Odyssey Cyber Security
   _T("ODFsFimFilter.sys"),
   _T("ODFsTokenFilter.sys"),
   _T("ODFsFilter.sys"),
   // OKUMA Corp
   _T("ospfile_mini.sys"),
   // OnMoon Company LLC
   _T("acdrv.sys"),
   // Palo Alto Networks
   _T("CyvrFsfd.sys"),
   // Panda Security
   _T("PSINPROC.SYS"),
   _T("PSINFILE.SYS"),
   _T("amfsm.sys"),
   _T("amm8660.sys"),
   _T("amm6460.sys"),
   // Panda Software
   _T("NanoAVMF.sys"),
   _T("shldflt.sys"),
   // Panzor Cybersecurity
   _T("pavdrv.sys"),
   // Paretologic
   _T("PLGFltr.sys"),
   // PC Tools Pty. Ltd.
   _T("PCTCore64.sys"),
   _T("PCTCore.sys"),
   _T("ikfilesec.sys"),
   // Perfect World Co. Ltd
   _T("PerfectWorldAntiCheatSys.sys"),
   // PerfectWorld Ltd
   _T("PWProtect.sys"),
   // PerSystems SA
   _T("pervac.sys"),
   // Pooyan System
   _T("RanPodFS.sys"),
   // PWI, Inc.
   _T("pwipf6.sys"),
   // Qihoo 360
   _T("dsark.sys"),
   _T("360avflt.sys"),
   // Quick Heal Technologies Pvt. Ltd.
   _T("snsrflt.sys"),
   _T("bdsflt.sys"),
   _T("arwflt.sys"),
   // Quick Heal TechnologiesPvt. Ltd.
   _T("ggc.sys"),
   _T("catflt.sys"),
   // ReaQta Ltd.
   _T("reaqtor.sys"),
   // Redstor Limited
   _T("RsFlt.sys"),
   // refractionPOINT
   _T("hcp_kernel_acq.sys"),
   // REVE Antivirus
   _T("ReveFltMgr.sys"),
   _T("ReveProcProtection.sys"),
   // S.N.Safe&Software
   _T("snscore.sys"),
   // Sangfor Technologies
   _T("sfavflt.sys"),
   // Savant Protection, Inc.
   _T("savant.sys"),
   // Scargo Inc
   _T("si32_file.sys"),
   _T("si64_file.sys"),
   // SECUI Corporation
   _T("sciptflt.sys"),
   _T("scifsflt.sys"),
   // SecuLution GmbH
   _T("ssvhook.sys"),
   // SecureAge Technology
   _T("sascan.sys"),
   // SecureBrain Corporation
   _T("mscan-rt.sys"),
   // SecureLink Inc.
   _T("zwPxeSvr.sys"),
   _T("zwASatom.sys"),
   // Securitas Technologies,Inc.
   _T("NovaShield.sys"),
   // SecurityCoverage, Inc.
   _T("SCFltr.sys"),
   // Segira LLC
   _T("SegiraFlt.sys"),
   // Segurmatica
   _T("SegMD.sys"),
   _T("SegMP.sys"),
   _T("SegF.sys"),
   // Sequretek IT
   _T("KawachFsMinifilter.sys"),
   // SGA
   _T("EPSMn.sys"),
   // SGRI Co., LTD.
   _T("vcMFilter.sys"),
   // SheedSoft Ltd
   _T("SheedAntivirusFilterDriver.sys"),
   // Shenzhen Tencent Computer Systems Company Limited
   _T("TSysCare.sys"),
   _T("TFsFlt.sys"),
   // Softwin
   _T("bdfsfltr.sys"),
   _T("bdfm.sys"),
   // Sophos
   _T("SophosED.sys"),
   _T("SAVOnAccess.sys"),
   _T("savonaccess.sys"),
   _T("sld.sys"),
   // SpellSecurity
   _T("spellmon.sys"),
   // Sybonic Systems Inc
   _T("THFilter.sys"),
   // symantec
   _T("eeCtrl.sys"),
   _T("eraser.sys"),
   _T("SRTSP.sys"),
   _T("SRTSPIT.sys"),
   _T("SRTSP64.SYS"),
   // Symantec
   _T("VirtualAgent.sys"),
   // Tall Emu
   _T("OADevice.sys"),
   // Technology Nexus AB
   _T("SE46Filter.sys"),
   // TEHTRI-Security
   _T("egambit.sys"),
   // Tencent
   _T("TesMon.sys"),
   _T("QQSysMonX64.sys"),
   _T("QQSysMon.sys"),
   // Teramind
   _T("tmfsdrv2.sys"),
   // TRAPMINE A.S.
   _T("trpmnflt.sys"),
   // Trend
   _T("tmpreflt.sys"),
   // Trend Micro Inc.
   _T("TmKmSnsr.sys"),
   _T("fileflt.sys"),
   _T("TmEsFlt.sys"),
   _T("TmEyes.sys"),
   _T("tmevtmgr.sys"),
   // Verdasys Inc
   _T("STKrnl64.sys"),
   // VisionPower Co.,Ltd.
   _T("PZDrvXP.sys"),
   // VMware, Inc.
   _T("vsepflt.sys"),
   _T("VFileFilter.sys(renamed)"),
   // WardWiz
   _T("WrdWizSecure64.sys"),
   _T("wrdwizscanner.sys"),
   // Webroot Inc.
   _T("WRAEKernel.sys"),
   _T("WRKrn.sys"),
   _T("WRCore.sys"),
   // Webroot Software, Inc.
   _T("ssfmonm.sys"),
   // White Cloud Security
   _T("WCSDriver.sys"),
   // WidgetNuri Corp
   _T("SoftFilterxxx.sys"),
   _T("RansomDefensexxx.sys"),
   // WINS CO. LTD
   _T("agentrtm64.sys"),
   _T("rswmon.sys"),
   // Yoggie
   _T("UFDFilter.sys"),
   // ZhengYong InfoTech LTD.
   _T("Zyfm.sys"),
   /*
   * FSFilter Anti-Virus - END
   */
   /*
   * FSFilter Activity Monitor - BEGIN
   */
   // (c)SMS
   _T("isafermon"),
   // 1mill
   _T("FSMon.sys"),
   // 360 Software (Beijing)
   _T("AtdrAgent.sys"),
   _T("AtdrAgent64.sys"),
   _T("Qutmdrv.sys"),
   // Absolute Software
   _T("cbfsfilter2017.sys"),
   // Acronis
   _T("NgScan.sys"),
   // Actifio Inc
   _T("aaf.sys"),
   // Adaptiva
   _T("AdaptivaClientCache32.sys"),
   _T("AdaptivaclientCache64.sys"),
   // Adtrustmedia
   _T("browserMon.sys"),
   // AhnLab, Inc.
   _T("VPDrvNt.sys"),
   // AI Consulting
   _T("aictracedrv_am.sys"),
   // Airlock Digital Pty Ltd
   _T("alcapture.sys"),
   // AIRWare Technology Ltd
   _T("airship-filter.sys"),
   // Alfa
   _T("AlfaFF.sys"),
   // Aliaksander Lebiadzevich
   _T("SDDrvLdr.sys"),
   // AlphaAntiLeak
   _T("AALProtect.sys"),
   // ALPS SYSTEM INTERGRATION CO.
   _T("ISIRMFmon.sys"),
   // Altaro Ltd.
   _T("altcbt.sys"),
   // ALWIL Software
   _T("aswFsBlk.sys"),
   // Amazon Web Services Inc
   _T("AmznMon.sys"),
   // Analytik Jena AG
   _T("ajfsprot.sys"),
   // ApexSQL LLC
   _T("ApexSqlFilterDriver.sys"),
   // AppGuard LLC
   _T("AGSysLock.sys"),
   _T("AGSecLock.sys"),
   // AppiXoft
   _T("axfsysmon.sys"),
   _T("scensemon.sys"),
   // AppSense Ltd
   _T("DataNow_Driver.sys"),
   _T("UcaFltDriver.sys"),
   // AppStream, Inc.
   _T("rflog.sys"),
   // ApSoft
   _T("CwMem2k64.sys"),
   // Aqua Security
   _T("ContainerMonitor.sys"),
   // Arcserve
   _T("xoiv8x64.sys"),
   // Arkoon Network Security
   _T("heimdall.sys"),
   // Ashampoo Development
   _T("IFS64.sys"),
   // AsiaInfo Technologies
   _T("kFileFlt.sys"),
   // Aternity Ltd
   _T("AternityRegistryHook.sys"),
   // Atlansys Software
   _T("atflt.sys"),
   _T("amfd.sys"),
   // Avanite Limited
   _T("AvaPsFD.sys"),
   // Avast Software
   _T("aswSP.sys"),
   // AVG Technologies CZ
   _T("avgtpx86.sys"),
   _T("avgtpx64.sys"),
   // Avira GmbH
   _T("avipbb.sys"),
   // AvSoft Technologies
   _T("strapvista.sys"),
   // Axact Pvt Ltd
   _T("axfltdrv.sys"),
   // Axur Information Sec.
   _T("amsfilter.sys"),
   // Backup Systems Ltd
   _T("cbfltfs4.sys"),
   // Baidu (beijing)
   _T("BdRdFolder.sys"),
   // Baidu (Hong Kong) Limited
   _T("Bfmon.sys"),
   // Baidu Online Network
   _T("bdsysmon.sys"),
   // Barkly Protects Inc.
   _T("BOsCmFlt.sys"),
   _T("BOsFsFltr.sys"),
   // Basein Networks
   _T("cbfsfilter2017.sys"),
   // BattlEye Innovations
   _T("BEDaisy.sys"),
   // Beijing CA-JinChen Software Co.
   _T("kfac.sys"),
   // Beijing QiAnXin Tech.
   _T("QmInspec.sys"),
   // Beijing Qihoo Technology Co.
   _T("360fsflt.sys"),
   // Beijing Shu Yan Science
   _T("GagSecurity.sys"),
   // Beijing Zhong Hang Jiaxin Computer Technology Co.,Ltd.
   _T("filefilter.sys"),
   // Best Security
   _T("rpwatcher.sys"),
   // BeyondTrust Inc.
   _T("BlackbirdFSA.sys"),
   // BicDroid Inc.
   _T("QDocumentREF.sys"),
   // Bit9 Inc.
   _T("CarbonBlackK.sys"),
   // BitArmor Systems, Inc
   _T("bapfecpt.sys"),
   _T("bamfltr.sys"),
   // Bitdefender SRL
   _T("edrsensor.sys"),
   _T("bdprivmon.sys"),
   // bitFence Inc.
   _T("bfaccess.sys"),
   // BiZone LLC
   _T("bzsenyaradrv.sys"),
   _T("bzsenspdrv.sys"),
   _T("bzsenth.sys"),
   // Blue Ridge Networks
   _T("BrnFileLock.sys"),
   _T("BrnSecLock.sys"),
   // Bluzen Inc
   _T("ipcomfltr.sys"),
   // Broadcom
   _T("symevnt.sys"),
   _T("symevnt32.sys"),
   // Bromium Inc
   _T("brfilter.sys"),
   _T("BrCow_x_x_x_x.sys"),
   _T("BemK.sys"),
   // ByStorm
   _T("BssAudit.sys"),
   // C-DAC Hyderabad
   _T("pecfilter.sys"),
   // CA
   _T("xomfcbt8x64.sys"),
   _T("KmxAgent.sys"),
   _T("KmxFile.sys"),
   _T("KmxSbx.sys"),
   // Carbonite Inc
   _T("MozyNextFilter.sys"),
   _T("MozyCorpFilter.sys"),
   _T("MozyEntFilter.sys"),
   _T("MozyOEMFilter.sys"),
   _T("MozyEnterpriseFilter.sys"),
   _T("MozyProFilter.sys"),
   _T("MozyHomeFilter.sys"),
   _T("BDSFilter.sys"),
   _T("CSBFilter.sys"),
   // cEncrypt
   _T("dsflt.sys"),
   // Centennial Software Ltd
   _T("msiodrv4.sys"),
   // Centre for Development of Advanced Computing
   _T("USBPDH.SYS"),
   // Centrify Corp
   _T("CentrifyFSF.sys"),
   // Certero
   _T("cmflt.sys"),
   // Chaewool
   _T("cFSfdrv"),
   // Check Point Software
   _T("epregflt.sys"),
   _T("epklib.sys"),
   // Checkpoint Software
   _T("cpepmon.sys"),
   // ChemoMetec
   _T("ChemometecFilter.sys"),
   // Cigent Technology Inc
   _T("Spotlight.sys"),
   // Cigital, Inc.
   _T("fmdrive.sys"),
   // Cisco Systems
   _T("csaam.sys"),
   // Citrix Systems
   _T("srminifilterdrv.sys"),
   // Clonix Co
   _T("rsfdrv.sys"),
   // Clumio Inc
   _T("ClumioChangeBlockMf.sys"),
   // Code42
   _T("Code42Filter.sys"),
   // ColorTokens
   _T("FFDriver.sys"),
   // Comae Tech
   _T("windd.sys"),
   // CommVault Systems, Inc.
   _T("CVCBT.sys"),
   // Comodo Security Solutions Inc.
   _T("CmdCwagt.sys"),
   _T("cfrmd.sys"),
   // ComTrade
   _T("ctamflt.sys"),
   // Comtrue Technology
   _T("shdlpSf.sys"),
   _T("ctrPAMon.sys"),
   _T("shdlpMedia.sys"),
   // Conduant Corporation
   _T("ConduantFSFltr.sys"),
   // Condusiv Technologies
   _T("hiofs.sys"),
   // CondusivTechnologies
   _T("vintmfs.sys"),
   _T("intmfs.sys"),
   _T("excfs.sys"),
   // Confio
   _T("IridiumSwitch.sys"),
   // CONNECT SHIFT LTD
   _T("DTPL.sys"),
   // CoSoSys
   _T("cssdlp.sys"),
   // Crawler Group
   _T("tbrdrv.sys"),
   // Credant Technologies
   _T("XendowFLT.sys"),
   // CristaLink
   _T("mtsvcdf.sys"),
   // CRU Data Security Group
   _T("CdsgFsFilter.sys"),
   // CyberArk Software
   _T("vfpd.sys"),
   _T("CybKernelTracker.sys"),
   // CyberSight Inc
   _T("csmon.sys"),
   // Cygna Labs
   _T("FileMonitor.sys"),
   // Cylance Inc.
   _T("CyOptics.sys"),
   _T("CyProtectDrv32.sys"),
   _T("CyProtectDrv64.sys"),
   // Cytrence Inc
   _T("cytmon.sys"),
   // Datacloak Tech
   _T("dcfsgrd.sys"),
   // DataGravity Inc.
   _T("dgfilter.sys"),
   // Datto Inc
   _T("DattoFSF.sys"),
   // Dell Secureworks
   _T("groundling32.sys"),
   _T("groundling64.sys"),
   // Dell Software Inc.
   _T("DgeDriver.sys"),
   // DELL Technologies
   _T("DTDSel.sys"),
   // Dell Technologies
   _T("NWEDriver.sys"),
   // derivo GmbH
   _T("bbfilter.sys"),
   // Digitalsense Co
   _T("dsfltfs.sys"),
   // Diskeeper Corporation
   _T("nowonmf.sys"),
   _T("dktlfsmf.sys"),
   _T("DKDrv.sys"),
   _T("DKRtWrt.sys"),
   _T("HBFSFltr.sys"),
   // Dmitry Stefankov
   _T("WinTeonMiniFilter.sys"),
   _T("wiper.sys"),
   _T("DevMonMiniFilter.sys"),
   // Doctor Web
   _T("Drwebfwflt.sys"),
   _T("EventMon.sys"),
   // Douzone Bizon Co
   _T("rswctrl.sys"),
   _T("mcstrg.sys"),
   _T("fmkkc.sys"),
   _T("nmlhssrv01.sys"),
   // DreamCrafts
   _T("SaMFlt.sys"),
   // Dtex Systems
   _T("dnaFSMonitor.sys"),
   // EaseVault Technologies Inc.
   _T("EaseFlt.sys"),
   // Egis Technology Inc.
   _T("eLock2FSCTLDriver.sys"),
   // Egnyte Inc
   _T("egnfsflt.sys"),
   // eIQnetworks Inc.
   _T("FIM.sys"),
   // Elex Tech Inc
   _T("iSafeKrnl.sys"),
   _T("iSafeKrnlMon.sys"),
   // eMingSoftware Inc
   _T("NetPeeker.sys"),
   // Encourage Technologies
   _T("asiofms.sys"),
   // Enterprise Data Solutions, Inc.
   _T("edsigk.sys"),
   // Entrust Inc.
   _T("eetd32.sys"),
   _T("eetd64.sys"),
   // ESET, spol. s r.o.
   _T("ehdrv.sys"),
   // ESTsoft corp.
   _T("EstPrmon.sys"),
   _T("Estprp.sys"),
   _T("EstRegmon.sys"),
   _T("EstRegp.sys"),
   // F-Secure
   _T("fshs.sys"),
   _T("fsatp.sys"),
   // Faronics Corporation
   _T("AeFilter.sys"),
   // FastTrack Software ApS
   _T("AbrPmon.sys"),
   // FFC Limited
   _T("FFCFILT.SYS"),
   // FileTek, Inc.
   _T("TrustedEdgeFfd.sys"),
   // FireEye Inc
   _T("WFP_MRT.sys"),
   // FireEye Inc.
   _T("FeKern.sys"),
   // Fitsec Ltd
   _T("kconv.sys"),
   _T("trace.sys"),
   _T("SandDriver.sys"),
   // Flexera Software Inc.
   _T("ISRegFlt.sys"),
   _T("ISRegFlt64.sys"),
   // ForcePoint LLC.
   _T("fpepflt.sys"),
   // Fujian Shen Kong
   _T("wats_se.sys"),
   // FUJITSU ENGINEERING
   _T("ibr2fsk.sys"),
   // FUJITSU LIMITED
   _T("FJGSDis2.sys"),
   _T("FJSeparettiFilterRedirect.sys"),
   _T("Fsw31rj1.sys"),
   _T("da_ctl.sys"),
   // FUJITSU SOCIAL SCIENCE
   _T("secure_os.sys"),
   // FUJITSU SOFTWARE
   _T("PsAcFileAccessFilter.sys"),
   // Fusion-io
   _T("fiometer.sys"),
   _T("dcSnapRestore.sys"),
   // Futuresoft
   _T("PointGuardVistaR32.sys"),
   _T("PointGuardVistaR64.sys"),
   _T("PointGuardVistaF.sys"),
   _T("PointGuardVista64F.sys"),
   // G Data Software AG
   _T("gddcv.sys"),
   // GameHi Co.
   _T("Codex.sys"),
   // GemacmbH
   _T("GcfFilter.sys"),
   // Glarysoft Ltd.
   _T("GUMHFilter.sys"),
   // Google, Inc.
   _T("MRxGoogle.sys"),
   // Gorizonty Rosta Ltd
   _T("GoFSMF.sys"),
   // GrammaTech, Inc.
   _T("drvhookcsmf.sys"),
   _T("drvhookcsmf_amd64.sys"),
   // Group-IB LTD
   _T("gibepcore.sys"),
   // HA Unix Pt
   _T("hafsnk.sys"),
   // Hangzhou Yifangyun
   _T("fangcloud_autolock_driver.sys"),
   // HAURI
   _T("secure_os_mf.sys"),
   // Hauri Inc
   _T("VrVBRFsFilter.sys"),
   _T("VrExpDrv.sys"),
   // HAVELSAN A.
   _T("HVLMinifilter.sys"),
   // HEAT Software
   _T("SK.sys"),
   // Heilig Defense LLC
   _T("HDRansomOffDrv.sys"),
   _T("HDCorrelateFDrv.sys"),
   _T("HDFileMon.sys"),
   // HeroBravo Technology
   _T("sysdiag.sys"),
   // Hexis Cyber Solutions
   _T("HexisFSMonitor.sys"),
   // HFN Inc.
   _T("RGNT.sys"),
   // Hitachi Solutions
   _T("hsmltmon.sys"),
   // Honeycomb Technologies
   _T("dskmn.sys"),
   // HP
   _T("hpreg.sys"),
   // i-Guard SAS
   _T("iGuard.sys"),
   // I-O DATA DEVICE
   _T("sConnect.sys"),
   // IBM
   _T("NmpFilter.sys"),
   _T("FsMonitor.sys"),
   // Idera
   _T("IderaFilterDriver.sys"),
   // Idera Software
   _T("SQLsafeFilterDriver.sys"),
   // IGLOO SECURITY, Inc.
   _T("kmNWCH.sys"),
   // IKARUS Security
   _T("Sonar.sys"),
   // Immidio B.V.
   _T("immflex.sys"),
   // in-soft Kft.
   _T("LmDriver.sys"),
   // INCA Internet Co.
   _T("GKPFCB.sys"),
   _T("GKPFCB64.sys"),
   // INCA Internet Co.,Ltd.
   _T("TkPcFtCb.sys"),
   _T("TkPcFtCb64.sys"),
   // Industrial Technology
   _T("icrlmonitor.sys"),
   // InfoCage
   _T("IccFilterSc.sys"),
   // Informzaschita
   _T("SnDacs.sys"),
   _T("SnExequota.sys"),
   // Infotecs
   _T("filenamevalidator.sys"),
   _T("KC3.sys"),
   // InfoWatch
   _T("iwhlp2.sys"),
   _T("iwhlpxp.sys"),
   _T("iwhlp.sys"),
   _T("iwdmfs.sys"),
   // Initech Inc.
   _T("INISBDrv64.sys"),
   // Int3 Software AB
   _T("equ8_helper.sys"),
   // Intel Corporation
   _T("ielcp.sys"),
   _T("IESlp.sys"),
   _T("IntelCAS.sys"),
   // Intercom Inc.
   _T("tsifilemon.sys"),
   _T("MarSpy.sys"),
   // Interset Inc.
   _T("WDCFilter.sys"),
   // Intronis Inc
   _T("VHDTrack.sys"),
   // Invincea
   _T("InvProtectDrv.sys"),
   _T("InvProtectDrv64.sys"),
   // Ionx Solutions LLP
   _T("AuditFlt.sys"),
   // ioScience
   _T("iothorfs.sys"),
   // iSecure Ltd.
   _T("isecureflt.sys"),
   // ITsMine
   _T("imfilter.sys"),
   // ITSTATION Inc
   _T("aUpDrv.sys"),
   // Ivanti
   _T("IvAppMon.sys"),
   // J's Communication Co.
   _T("RevoNetDriver.sys"),
   // Jinfengshuntai
   _T("IPFilter.sys"),
   // JiranData Co. Ltd
   _T("JDPPWF.sys"),
   _T("JDPPSF.sys"),
   // Jiransoft Co., Ltd
   _T("offsm.sys"),
   _T("xkfsfd.sys"),
   _T("JKPPOB.sys"),
   _T("JKPPXK.sys"),
   _T("JKPPPF.sys"),
   _T("JKPPOK.sys"),
   _T("pcpifd.sys"),
   // k4solution Co.
   _T("zsfprt.sys"),
   // Kalpataru
   _T("GPMiniFIlter.sys"),
   // Kaspersky Lab
   _T("klboot.sys"),
   _T("klfdefsf.sys"),
   _T("klrsps.sys"),
   _T("klsnsr.sys"),
   _T("klifks.sys"),
   _T("klifaa.sys"),
   _T("Klifsm.sys"),
   // KEBA AG
   _T("KeWF.sys"),
   // Kenubi
   _T("boxifier.sys"),
   // Keysight Technologies
   _T("KtFSFilter.sys"),
   // kingsoft
   _T("Kisknl.sys"),
   // Kits Ltd.
   _T("cbfsfilter2017.sys"),
   // KnowledgeTree Inc.
   _T("ktsyncfsflt.sys"),
   // Koby Kahane
   _T("NpEtw.sys"),
   // Ladislav Zezula
   _T("MSpy.sys"),
   // LANDESK Software
   _T("LDSecDrv.sys"),
   // Lenovo Beijing
   _T("slb_guard.sys"),
   _T("lrtp.sys"),
   // LINK co.
   _T("NetAccCtrl.sys"),
   _T("NetAccCtrl64.sys"),
   // Livedrive Internet Ltd
   _T("LivedriveFilter.sys"),
   // Logichron Inc
   _T("CatMF.sys"),
   // LogRhythm Inc.
   _T("LRAgentMF.sys"),
   // Lovelace Network Tech
   _T("MPKernel.sys"),
   // Lumension
   _T("eps.sys"),
   // Magic Softworks, Inc.
   _T("MagicBackupMonitor.sys"),
   // magrasoft Ltd
   _T("zqFilter.sys"),
   // MailRu
   _T("mracdrv.sys"),
   // Malwarebytes
   _T("mbamshuriken.sys"),
   // Man Technology Inc
   _T("bsrfsflt.sys"),
   _T("fsrfilter.sys"),
   _T("vollock.sys"),
   _T("drbdlock.sys"),
   // ManageEngine Zoho
   _T("DFMFilter.sys"),
   _T("DCFAFilter.sys"),
   _T("RMPHVMonitor.sys"),
   _T("FAPMonitor.sys"),
   _T("MEARWFltDriver.sys"),
   // ManTech
   _T("topdogfsfilt.sys"),
   // March Hare Software Ltd
   _T("evscase.sys"),
   _T("inuse.sys"),
   _T("cvsflt.sys"),
   // McAfee
   _T("mfencfilter.sys"),
   // McAfee Inc.
   _T("mfeaskm.sys"),
   // Micro Focus
   _T("FilrDriver.sys"),
   // Microsoft
   _T("DhWatchdog.sys"),
   _T("mssecflt.sys"),
   _T("Backupreader.sys"),
   _T("MsixPackagingToolMonitor.sys"),
   _T("AppVMon.sys"),
   _T("DpmFilter.sys"),
   _T("Procmon11.sys"),
   _T("minispy.sys"),
   _T("fdrtrace.sys"),
   _T("filetrace.sys"),
   _T("uwfreg.sys"),
   _T("uwfs.sys"),
   _T("locksmith.sys"),
   _T("winload.sys"),
   _T("CbSampleDrv.sys"),
   _T("simrep.sys"),
   _T("change.sys"),
   _T("delete_flt.sys"),
   _T("SmbResilFilter.sys"),
   _T("usbtest.sys"),
   _T("NameChanger.sys"),
   _T("failMount.sys"),
   _T("failAttach.sys"),
   _T("stest.sys"),
   _T("cdo.sys"),
   _T("ctx.sys"),
   _T("fmm.sys"),
   _T("cancelSafe.sys"),
   _T("message.sys"),
   _T("passThrough.sys"),
   _T("nullFilter.sys"),
   _T("ntest.sys"),
   _T("iiscache.sys"),
   _T("wrpfv.sys"),
   _T("msnfsflt.sys"),
   // Mobile Content Mgmt
   _T("cbfsfilter2017.sys"),
   // MRY Inc.
   _T("drsfile.sys"),
   // NanJing Geomarking
   _T("MagicProtect.sys"),
   _T("cbfsfilter2017.sys"),
   _T("cbfsfilter2020.sys"),
   // NEC Corporation
   _T("UVMCIFSF.sys"),
   // NEC Soft
   _T("flyfs.sys"),
   _T("serfs.sys"),
   _T("hdrfs.sys"),
   // NEC System Technologies
   _T("IccFilterAudit.sys"),
   // NEC System Technologies,Ltd.
   _T("ICFClientFlt.sys"),
   _T("IccFileIoAd.sys"),
   // Neowiz Corporation
   _T("MWatcher.sys"),
   // NetIQ
   _T("CGWMF.sys"),
   // NetLib
   _T("nlcbhelpx86.sys"),
   _T("nlcbhelpx64.sys"),
   _T("nlcbhelpi64.sys"),
   // NetVision, Inc.
   _T("nvmon.sys"),
   // Network Appliance
   _T("flashaccelfs.sys"),
   _T("changelog.sys"),
   // NetworkProfi Ltd
   _T("laFS.sys"),
   // New Net Technologies Limited
   _T("NNTInfo.sys"),
   // NewSoftwares.net,Inc.
   _T("WinFLAHdrv.sys"),
   _T("WinFLAdrv.sys"),
   _T("WinDBdrv.sys"),
   _T("WinFLdrv.sys"),
   _T("WinFPdrv.sys"),
   // NEXON KOREA
   _T("BlackCat.sys"),
   // NextLabs
   _T("nxrmflt.sys"),
   // Niriva LLC
   _T("VHDDelta.sys"),
   _T("FSTrace.sys"),
   // Nomadesk
   _T("cbfltfs4.sys"),
   // Novell
   _T("zesfsmf.sys"),
   // NTP Software
   _T("ntps_fa.sys"),
   // Nurd Yazilim A.S.
   _T("edrdrv.sys"),
   // NURILAB
   _T("pfracdrv.sys"),
   _T("nrcomgrdki.sys"),
   _T("nrcomgrdka.sys"),
   _T("nrpmonki.sys"),
   _T("nrpmonka.sys"),
   _T("nravwka.sys"),
   _T("bhkavki.sys"),
   _T("bhkavka.sys"),
   _T("docvmonk.sys"),
   _T("docvmonk64.sys"),
   // NVELO Inc.
   _T("SamsungRapidFSFltr.sys"),
   // OCZ Storage
   _T("OczMiniFilter.sys"),
   // OnGuard Systems LLC
   _T("NlxFF.sys"),
   // OpenText Corp
   _T("enmon.sys"),
   // OPSWAT Inc.
   _T("libwamf.sys"),
   // ORANGE WERKS Inc
   _T("wgfile.sys"),
   // PA File Sight
   _T("FileSightMF.sys"),
   // Packeteer
   _T("mblmon.sys"),
   // Palo Alto Networks
   _T("tedrdrv.sys"),
   // PHD Virtual Tech Inc.
   _T("phdcbtdrv.sys"),
   // PJSC KP VTI
   _T("RW7FsFlt.sys"),
   // PolyLogyx LLC
   _T("vast.sys"),
   // Positive Technologies
   _T("mpxmon.sys"),
   // Protected Networks
   _T("minitrc.sys"),
   // Qihoo 360
   _T("360box.sys"),
   // Qingdao Ruanmei Network Technology Co.
   _T("RMDiskMon.sys"),
   _T("diskactmon.sys"),
   // Quality Corporation
   _T("qfmon.sys"),
   // Qualys Inc.
   _T("QMON.sys"),
   _T("qfimdvr.sys"),
   // Quantum Corporation.
   _T("cvofflineFlt32.sys"),
   _T("cvofflineFlt64.sys"),
   // Quest Software
   _T("QFAPFlt.sys"),
   // Quest Software Inc.
   _T("BWFSDrv.sys"),
   _T("CAADFlt.sys"),
   // Quick Heal Technologies Pvt. Ltd.
   _T("sieflt.sys"),
   _T("cssdlp.sys"),
   _T("fam.sys"),
   // Quorum Labs
   _T("qfilter.sys"),
   // Rackware
   _T("rwchangedrv.sys"),
   // Redstor Limited
   _T("RsFlt.sys"),
   // RES Software
   _T("FileGuard.sys"),
   _T("NetGuard.sys"),
   _T("RegGuard.sys"),
   _T("ImgGuard.sys"),
   _T("AppGuard.sys"),
   // Resplendence Software Projects
   _T("mmPsy32.sys"),
   _T("mmPsy64.sys"),
   _T("rrMon32.sys"),
   _T("rrMon64.sys"),
   // rhipe Australia Pty
   _T("SeRdr.sys"),
   // Rubrik Inc
   _T("RubrikFileAudit.sys"),
   _T("FileSystemCBT.sys"),
   // rubysoft
   _T("IronGateFD.sys"),
   // RuiGuard Ltd
   _T("RuiMinispy.sys"),
   _T("RuiFileAccess.sys"),
   _T("RuiEye.sys"),
   _T("RuiMachine.sys"),
   _T("RuiDiskFs.sys"),
   // RUNEXY
   _T("ruaff.sys"),
   _T("mlsaff.sys"),
   // SAFE-Cyberdefense
   _T("SAFE-Agent.sys"),
   // Safend
   _T("Sahara.sys"),
   _T("Santa.sys"),
   // SaferZone Co.
   _T("SZEDRDrv.sys"),
   _T("szardrv.sys"),
   _T("szpcmdrv.sys"),
   _T("szdfmdrv.sys"),
   _T("szdfmdrv_usb.sys"),
   _T("sprtdrv.sys"),
   // Samsung SDS Ltd
   _T("SGResFlt.sys"),
   // SanDisk Inc.
   _T("fiopolicyfilter.sys"),
   // Sandoll Communication
   _T("SfdFilter.sys"),
   // SC ODEKIN SOLUTIONS SRL
   _T("ospmon.sys"),
   // Scalable Software Inc.
   _T("PkgFilter.sys"),
   // ScriptLogic
   _T("FSAFilter.sys"),
   // Secdo
   _T("SecdoDriver.sys"),
   // SecureAxis
   _T("usbl_ifsfltr.sys"),
   // SecureAxis Software
   _T("llfilter.sys"),
   // Secured Globe Inc.
   _T("fltRs329.sys"),
   // SecureLink Inc.
   _T("CBFSFilter2017.sys"),
   // Security Code LLC
   _T("ScAuthFSFlt.sys"),
   _T("ScAuthIoDrv.sys"),
   // SentinelOne
   _T("SentinelMonitor.sys"),
   // Sevtechnotrans
   _T("uamflt.sys"),
   // Shanghai YiCun Network Tech Co. Ltd
   _T("AccessValidator.sys"),
   // SharpCrafters
   _T("psisolator.sys"),
   // SheedSoft Ltd
   _T("SheedSelfProtection.sys"),
   // SheedSoft Ltd.
   _T("arta.sys"),
   // Shenzhen CloudRiver
   _T("CrUnCopy.sys"),
   // SHENZHEN UNNOO Information Techco.
   _T("RyGuard.sys"),
   _T("FileShareMon.sys"),
   _T("ryfilter.sys"),
   // Shenzhen Unnoo LTD
   _T("secufile.sys"),
   _T("XiaobaiFs.sys"),
   _T("XiaobaiFsR.sys"),
   // ShinNihonSystec Co
   _T("sagntflt.sys"),
   // Simopro Technology
   _T("CbFltFs4.sys"),
   // SK Infosec Co
   _T("PLPOffDrv.sys"),
   _T("ISFPDrv.sys"),
   _T("ionmonwdrv.sys"),
   // Sky Co., LTD.
   _T("SkyRGDrv.sys"),
   _T("SkyAMDrv.sys"),
   // Sky Co.,Ltd.
   _T("SkyWPDrv.sys"),
   // SmartFile LLC
   _T("FileHubAgent.sys"),
   // SMTechnology Co.
   _T("storagedrv.sys"),
   // SN Systems Ltd
   _T("cbfilter20.sys"),
   _T("cbfsfilter2017.sys"),
   // SnoopWall LLC
   _T("SWCommFltr.sys"),
   // SODATSW
   _T("sodatpfl.sys"),
   // SODATSW spol. s r.o.
   _T("sodatpfl.sys"),
   _T("fcontrol.sys"),
   // SoftCamp Co.
   _T("scred.sys"),
   // Softnext Technologies
   _T("snimg.sys"),
   // SoftPerfect Research
   _T("fsnk.sys"),
   // Software Pursuits Inc.
   _T("SPIMiniFilter.sys"),
   // Sogou Ltd.
   _T("SCAegis.sys"),
   // Solarwinds LLC
   _T("SWFsFltrv2.sys"),
   _T("SWFsFltr.sys"),
   // Soliton Systems
   _T("it2reg.sys"),
   _T("it2drv.sys"),
   _T("solitkm.sys"),
   // Soliton Systems K.K.
   _T("SDVFilter.sys"),
   // Solusseum Inc
   _T("Sefo.sys"),
   // Soluto LTD
   _T("PDGenFam.sys"),
   // Somma Inc
   _T("MonsterK.sys"),
   // SonicWall Inc
   _T("SFPMonitor.sys"),
   // Sophos
   _T("SophosED.sys"),
   // Sophos Plc
   _T("soidriver.sys"),
   // SoulFrost
   _T("sfac.sys"),
   // SPEKNET EOOD
   _T("Asgard.sys"),
   // Spharsoft Technologies
   _T("SvCBT.sys"),
   // Squadra Technologies
   _T("secRMM.sys"),
   // Stegosystems Inc
   _T("StegoProtect.sys"),
   // StorageCraft Tech
   _T("stcvsm.sys"),
   // Stormshield
   _T("EsProbe.sys"),
   // Sumitomo Electric Ltd.
   _T("MCFileMon64.sys"),
   _T("MCFileMon32.sys"),
   // Sun&Moon Rise
   _T("ntfsf.sys"),
   // Symantec
   _T("pgpwdefs.sys"),
   _T("GEProtection.sys"),
   _T("sysMon.sys"),
   _T("ssrfsf.sys"),
   _T("emxdrv2.sys"),
   _T("reghook.sys"),
   _T("spbbcdrv.sys"),
   _T("bhdrvx86.sys"),
   _T("bhdrvx64.sys"),
   _T("SISIPSFileFilter"),
   _T("symevent.sys"),
   // Symantec Corp.
   _T("diflt.sys"),
   // Syncopate
   _T("thetta.sys"),
   // Systemneeds, Inc
   _T("Snilog.sys"),
   // TaaSera Inc.
   _T("AwareCore.sys"),
   // Tanium
   _T("TaniumRecorderDrv.sys"),
   // TCXA Ltd.
   _T("fcnotify.sys"),
   // Tech Research
   _T("FASDriver"),
   // TechnoKom Ltd.
   _T("agfsmon.sys"),
   // Telefnica Digital
   _T("path8flt.sys"),
   // Temasoft S.R.L.
   _T("filemon.sys"),
   // Tencent (Shenzhen)
   _T("QQProtect.sys"),
   _T("QQProtectX64.sys"),
   // Tencent Technology
   _T("TenRSafe2.sys"),
   _T("tesxporter.sys"),
   _T("tesxnginx.sys"),
   // Tetraglyph Technologies
   _T("TGFSMF.sys"),
   // ThinAir Labs Inc
   _T("taobserveflt.sys"),
   // ThinScale Tech
   _T("TSTFsReDir.sys"),
   _T("TSTRegReDir.sys"),
   _T("TSTFilter.sys"),
   // Third Brigade
   _T("tbfsfilt.sys"),
   // Threat Stack
   _T("ThreatStackFIM.sys"),
   // Tiversa Inc
   _T("tss.sys"),
   // Topology Ltd
   _T("dsfemon.sys"),
   // Tranxition Corp
   _T("regmonex.sys"),
   _T("TXRegMon.sys"),
   // Trend Micro Inc.
   _T("TMUMS.sys"),
   _T("hfileflt.sys"),
   _T("TMUMH.sys"),
   // Trend Micro, Inc.
   _T("AcDriver.sys"),
   _T("SakFile.sys"),
   _T("SakMFile.sys"),
   // Tritium Inc.
   _T("Tritiumfltr.sys"),
   // Trustware Ltd
   _T("Redlight.sys"),
   // Trustwave
   _T("TWBDCFilter.sys"),
   // UpGuard
   _T("UpGuardRealTime.sys"),
   // Varlook Ltd.
   _T("varpffmon.sys"),
   // Varonis Ltd
   _T("VrnsFilter.sys"),
   // Veramine Inc
   _T("phantomd.sys"),
   // Vidder Inc.
   _T("vidderfs.sys"),
   // Viewfinity
   _T("vfdrv.sys"),
   // Vision Solutions
   _T("repdrv.sys"),
   _T("repmon.sys"),
   // VMware, Inc.
   _T("VMWVvpfsd.sys"),
   _T("RTOLogon.sys"),
   // VoodooSoft
   _T("VSScanner.sys"),
   // WaikatoLink Ltd
   _T("proggerdriver.sys"),
   // WardWiz
   _T("WRDWIZFILEPROT.SYS"),
   _T("WRDWIZREGPROT.SYS"),
   // Warp Disk Software
   _T("DsDriver.sys"),
   // Weing Co.,Ltd.
   _T("pscff.sys"),
   // Wellbia.com
   _T("xhunter64.sys"),
   _T("uncheater.sys"),
   // Wellbiacom
   _T("xhunter1.sys"),
   // Whitebox Security
   _T("wbfilter.sys"),
   // WhiteCell Software Inc.
   _T("EGMinFlt.sys"),
   // WidgetNuri Corp
   _T("wsafefilter.sys"),
   _T("RansomDetect.sys"),
   // Winicssec Ltd
   _T("wlminisecmod.sys"),
   _T("WntGPDrv.sys"),
   // X-Cloud Systems
   _T("xcpl.sys"),
   // Xacti
   _T("stflt.sys"),
   // Yahoo Japan Corporation
   _T("YahooStorage.sys"),
   // Yandex LLC
   _T("bmregdrv.sys"),
   _T("bmfsdrv.sys"),
   // YATEM Co. Ltd.
   _T("LCmPrintMon.sys"),
   _T("LCgAdMon.sys"),
   _T("LCmAdMon.sys"),
   _T("LCgFileMon.sys"),
   _T("LCmFile.sys"),
   _T("LCgFile.sys"),
   _T("LCmFileMon.sys"),
   // Yokogawa Corpration
   _T("YFSD2.sys"),
   // Yokogawa R&L Corp
   _T("YFSDR.SYS"),
   _T("YFSD.SYS"),
   _T("YFSRD.sys"),
   _T("psgfoctrl.sys"),
   _T("psgdflt.sys"),
   // Zampit
   _T("zampit_ml.sys"),
   // ZenmuTech Inc.
   _T("mumdi.sys"),
   // Zhuan Zhuan Jing Shen
   _T("zzpensys.sys"),
   // ZoneFox
   _T("KernelAgent32.sys"),
   /*
   * FSFilter Activity Monitor - END
   */
   /*
   * Invoke-EDRCheck.ps1 - BEGIN
   * Duplicates from previous source are removed.
   */
   // Altiris Symantec
   _T("atrsdfw.sys"),
   // Avast
   _T("naswSP.sys"),
   // Carbon Black
   _T("CbELAM.sys"),
   _T("ctifile.sys"),
   _T("ctinet.sys"),
   _T("parity.sys"),
   // Cisco
   _T("csacentr.sys"),
   _T("csaenh.sys"),
   _T("csareg.sys"),
   _T("csascr.sys"),
   // CJSC Returnil Software
   _T("rvsavd.sys"),
   // Comodo Security
   _T("CmdMnEfs.sys"),
   _T("MyDLPMF.sys"),
   // CrowdStrike
   _T("im.sys"),
   _T("CSDeviceControl.sys"),
   _T("CSFirmwareAnalysis.sys"),
   // Cybereason
   _T("CRExecPrev.sys"),
   // Endgame
   _T("esensor.sys"),
   // ESET
   _T("edevmon.sys"),
   // F-Secure
   _T("xfsgk.sys"),
   // Malwarebytes
   _T("mbamwatchdog.sys"),
   // Microsoft Defender
   _T("MpKslDrv.sys"),
   // Palo Alto Networks - Cortex XDR
   _T("cyverak.sys"),
   _T("cyvrlpc.sys"),
   _T("cyvrmtgn.sys"),
   _T("tdevflt.sys"),
   // Raytheon Cyber Solutions
   _T("eaw.sys"),
   // Symantec
   _T("vxfsrep.sys"),
   _T("VirtFile.sys"),
   _T("SymAFR.sys"),
   _T("symefasi.sys"),
   _T("symefa.sys"),
   _T("symefa64.sys"),
   _T("SymHsm.sys"),
   _T("evmf.sys"),
   _T("GEFCMP.sys"),
   _T("VFSEnc.sys"),
   _T("pgpfs.sys"),
   _T("fencry.sys"),
   _T("symrg.sys"),
   // Verdasys Inc
   _T("ndgdmk.sys"),
   /*
   * Invoke-EDRCheck.ps1 - END
   */

   /*
   * User contributions
   */
   // Tehtris
   _T("egfilterk.sys"),
   // Sophos
   _T("SophosDt2.sys"),
   _T("SophosSupport.sys"),
   // Cisco AMP
   _T("ExPrevDriver.sys"),
};

BOOL isFileSignatureMatchingEDR(TCHAR* filePath) {
    SignatureOpsError returnValue;
    TCHAR* signers = NULL;
    size_t szSigners = 0;
    returnValue = GetFileSigners(filePath, signers, &szSigners);

    // Expected if the file is signed, first call will return the needed buffer size.
    if (returnValue == E_INSUFFICIENT_BUFFER) {
        signers = calloc(szSigners, sizeof(TCHAR));
        if (!signers) {
            _tprintf_or_not(TEXT("[!] Couldn't allocate memory for Signers information for binary \"%s\"\n"), filePath);
            return FALSE;
        }
        returnValue = GetFileSigners(filePath, signers, &szSigners);
    }

    // If the file is not signed, it's unlikely to be linked to an EDR product.
    if (returnValue == E_NOT_SIGNED) {
        // _tprintf_or_not(TEXT("[*] File \"%s\" is not signed.\n"), binaryPath);
        return FALSE;
    }

    if (returnValue == E_FILE_NOT_FOUND) {
        _tprintf_or_not(TEXT("[!] Couldn't locate file \"%s\" to retrieve certificate information.\n"), filePath);
        return FALSE;
    }

    if ((returnValue != E_SUCCESS) || !signers) {
        _tprintf_or_not(TEXT("[!] An error occurred while retrieving certificate information for file \"%s\"\n"), filePath);
        return FALSE;
    }

    // Iterates over each keywords in EDR_SIGNATURE_KEYWORDS and return TRUE if a match is found.
    for (int i = 0; i < _countof(EDR_SIGNATURE_KEYWORDS); ++i) {
        if (_tcsstr(signers, EDR_SIGNATURE_KEYWORDS[i])) {
            free(signers);
            return TRUE;
        }
    }

    free(signers);
    return FALSE;
}

BOOL isBinaryNameMatchingEDR(TCHAR* binaryName) {
    for (int i = 0; i < _countof(EDR_BINARIES); ++i) {
        if (_tcscmp(binaryName, EDR_BINARIES[i]) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOL isBinaryPathMatchingEDR(TCHAR* binaryPath) {
    for (int i = 0; i < _countof(EDR_BINARIES); ++i) {
        if (_tcsstr(binaryPath, EDR_BINARIES[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOL isDriverNameMatchingEDR(TCHAR* driverName) {
    for (int i = 0; i < _countof(EDR_DRIVERS); ++i) {
        if (_tcscmp(driverName, EDR_DRIVERS[i]) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOL isDriverPathMatchingEDR(TCHAR* driverPath) {
    for (int i = 0; i < _countof(EDR_DRIVERS); ++i) {
        if (_tcsstr(driverPath, EDR_DRIVERS[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

// TODO : create an API to check, with only the name of a loaded driver, if it an EDR (check its name against the hardcoded list of names, automatically find its path on disk and check the file signature)