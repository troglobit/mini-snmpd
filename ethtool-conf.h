/* Linux ethtool helpers
 *
 * Copyright (C) 2020  Bjørn Mork <bjorn@mork.no>
 *
 * This file may be distributed and/or modified under the terms of the
 * GNU General Public License version 2 as published by the Free Software
 * Foundation and appearing in the file LICENSE.GPL included in the
 * packaging of this file.
 *
 * This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
 * WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See COPYING for GPL licensing information.
 */

#ifndef ETHTOOL_CONF_H_
#define ETHTOOL_CONF_H_

#include <confuse.h>
#include "config.h"

#ifdef CONFIG_ENABLE_ETHTOOL

extern cfg_opt_t ethtool_opts[];
void ethtool_xlate_cfg(cfg_t *cfg);
#define CFG_ETHTOOL_SEC		CFG_SEC("ethtool", ethtool_opts, CFGF_MULTI | CFGF_TITLE | CFGF_NO_TITLE_DUPES),

#else

#define ethtool_xlate_cfg(cfg) do {} while (0)
#define CFG_ETHTOOL_SEC

#endif

#endif
