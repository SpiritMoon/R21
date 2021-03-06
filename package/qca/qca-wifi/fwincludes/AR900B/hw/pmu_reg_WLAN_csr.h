//                                                                             
// File:       ./pmu_reg_WLAN_csr.vrh                                          
// Creator:    shung                                                           
// Time:       Monday Apr 23, 2012 [6:26:15 pm]                                
//                                                                             
// Path:       /trees/shung/shung-dev/chips/peregrine/1.0/dv/soc/src/ave/regs/blueprint
// Arguments:  /cad/denali/blueprint/3.7.4//Linux/blueprint -odir . -codegen   
//             ath_vrh.codegen -ath_vrh -Wdesc -I                              
//             /trees/shung/shung-dev/chips/peregrine/1.0/blueprint/sysconfig  
//             pmu_reg_WLAN_csr.rdl                                            
//                                                                             
// Sources:    /trees/shung/shung-dev/chips/peregrine/1.0/ip/radio_peregrine/rtl/srif/blueprint/pmu_reg_WLAN.rdl
//             /trees/shung/shung-dev/chips/peregrine/1.0/env/blueprint/ath_vrh.pm
//                                                                             
// Blueprint:   3.7.4 (Tue Jun 23 00:17:01 PDT 2009)                           
// Machine:    vnc2                                                            
// OS:         Linux 2.4.21-40.ELsmp                                           
// Description:                                                                
//                                                                             
// No Description Provided                                                     
//                                                                             
//                                                                             


#ifndef _PMU_REG_WLAN_CSR_H_
#define _PMU_REG_WLAN_CSR_H_
// 0x0000 (WLAN_PMU1)
#define WLAN_PMU1_SWREG_MSB                                          31
#define WLAN_PMU1_SWREG_LSB                                          0
#define WLAN_PMU1_SWREG_MASK                                         0xffffffff
#define WLAN_PMU1_SWREG_GET(x)                                       (((x) & WLAN_PMU1_SWREG_MASK) >> WLAN_PMU1_SWREG_LSB)
#define WLAN_PMU1_SWREG_SET(x)                                       (((0 | (x)) << WLAN_PMU1_SWREG_LSB) & WLAN_PMU1_SWREG_MASK)
#define WLAN_PMU1_SWREG_RESET                                        805951696
#define WLAN_PMU1_ADDRESS                                            0x0000
#define WLAN_PMU1_HW_MASK                                            0xffffffff
#define WLAN_PMU1_SW_MASK                                            0xffffffff
#define WLAN_PMU1_HW_WRITE_MASK                                      0x00000000
#define WLAN_PMU1_SW_WRITE_MASK                                      0xffffffff
#define WLAN_PMU1_RSTMASK                                            0xffffffff
#define WLAN_PMU1_RESET                                              0x3009d8d0

// 0x0004 (WLAN_PMU2)
#define WLAN_PMU2_SWREGMSB_MSB                                       31
#define WLAN_PMU2_SWREGMSB_LSB                                       22
#define WLAN_PMU2_SWREGMSB_MASK                                      0xffc00000
#define WLAN_PMU2_SWREGMSB_GET(x)                                    (((x) & WLAN_PMU2_SWREGMSB_MASK) >> WLAN_PMU2_SWREGMSB_LSB)
#define WLAN_PMU2_SWREGMSB_SET(x)                                    (((0 | (x)) << WLAN_PMU2_SWREGMSB_LSB) & WLAN_PMU2_SWREGMSB_MASK)
#define WLAN_PMU2_SWREGMSB_RESET                                     0
#define WLAN_PMU2_PGM_MSB                                            21
#define WLAN_PMU2_PGM_LSB                                            21
#define WLAN_PMU2_PGM_MASK                                           0x00200000
#define WLAN_PMU2_PGM_GET(x)                                         (((x) & WLAN_PMU2_PGM_MASK) >> WLAN_PMU2_PGM_LSB)
#define WLAN_PMU2_PGM_SET(x)                                         (((0 | (x)) << WLAN_PMU2_PGM_LSB) & WLAN_PMU2_PGM_MASK)
#define WLAN_PMU2_PGM_RESET                                          0
#define WLAN_PMU2_USE_WLAN_SETTING_MSB                               20
#define WLAN_PMU2_USE_WLAN_SETTING_LSB                               20
#define WLAN_PMU2_USE_WLAN_SETTING_MASK                              0x00100000
#define WLAN_PMU2_USE_WLAN_SETTING_GET(x)                            (((x) & WLAN_PMU2_USE_WLAN_SETTING_MASK) >> WLAN_PMU2_USE_WLAN_SETTING_LSB)
#define WLAN_PMU2_USE_WLAN_SETTING_SET(x)                            (((0 | (x)) << WLAN_PMU2_USE_WLAN_SETTING_LSB) & WLAN_PMU2_USE_WLAN_SETTING_MASK)
#define WLAN_PMU2_USE_WLAN_SETTING_RESET                             0
#define WLAN_PMU2_DISC_BIT_LOCAL_MSB                                 19
#define WLAN_PMU2_DISC_BIT_LOCAL_LSB                                 19
#define WLAN_PMU2_DISC_BIT_LOCAL_MASK                                0x00080000
#define WLAN_PMU2_DISC_BIT_LOCAL_GET(x)                              (((x) & WLAN_PMU2_DISC_BIT_LOCAL_MASK) >> WLAN_PMU2_DISC_BIT_LOCAL_LSB)
#define WLAN_PMU2_DISC_BIT_LOCAL_SET(x)                              (((0 | (x)) << WLAN_PMU2_DISC_BIT_LOCAL_LSB) & WLAN_PMU2_DISC_BIT_LOCAL_MASK)
#define WLAN_PMU2_DISC_BIT_LOCAL_RESET                               0
#define WLAN_PMU2_SPARE_MSB                                          18
#define WLAN_PMU2_SPARE_LSB                                          0
#define WLAN_PMU2_SPARE_MASK                                         0x0007ffff
#define WLAN_PMU2_SPARE_GET(x)                                       (((x) & WLAN_PMU2_SPARE_MASK) >> WLAN_PMU2_SPARE_LSB)
#define WLAN_PMU2_SPARE_SET(x)                                       (((0 | (x)) << WLAN_PMU2_SPARE_LSB) & WLAN_PMU2_SPARE_MASK)
#define WLAN_PMU2_SPARE_RESET                                        0
#define WLAN_PMU2_ADDRESS                                            0x0004
#define WLAN_PMU2_HW_MASK                                            0xffffffff
#define WLAN_PMU2_SW_MASK                                            0xffffffff
#define WLAN_PMU2_HW_WRITE_MASK                                      0x00000000
#define WLAN_PMU2_SW_WRITE_MASK                                      0xffffffff
#define WLAN_PMU2_RSTMASK                                            0xffffffff
#define WLAN_PMU2_RESET                                              0x00000000


#endif /* _PMU_REG_WLAN_CSR_H_ */
