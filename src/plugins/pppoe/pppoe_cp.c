/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Intel and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */

#include <pppoe/pppoe.h>

int
pppoe_add_del_cp (u32 cp_if_index, u32 dp_if_index, u8 is_add)
{
  pppoe_main_t *pem = &pppoe_main;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *dp_hw = NULL;

  if (cp_if_index == ~0 || dp_if_index == ~0)
    {
      return VNET_API_ERROR_INVALID_ARGUMENT;
    }

  if (cp_if_index == dp_if_index)
    {
      return VNET_API_ERROR_INVALID_ARGUMENT;
    }

  if (!vnet_sw_interface_is_sub (vnm, dp_if_index))
    {
      dp_hw = vnet_get_hw_interface (vnm, dp_if_index);

      if (dp_hw->hw_class_index != ethernet_hw_interface_class.index)
	{
	  return VNET_API_ERROR_NON_ETHERNET;
	}
    }

  vnet_feature_enable_disable ("device-input", "pppoe-input", cp_if_index,
			       is_add, 0, 0);

  if (is_add)
    {
      if (dp_if_index < vec_len (pem->cp_if_index_by_sw_if_index) &&
	  pem->cp_if_index_by_sw_if_index[dp_if_index] != ~0)
	{
	  return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;
	}

      if (cp_if_index < vec_len (pem->dp_if_index_by_sw_if_index) &&
	  pem->dp_if_index_by_sw_if_index[cp_if_index] != ~0)
	{
	  return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;
	}

      vec_validate_init_empty (pem->cp_if_index_by_sw_if_index, dp_if_index,
			       ~0);
      pem->cp_if_index_by_sw_if_index[dp_if_index] = cp_if_index;

      vec_validate_init_empty (pem->dp_if_index_by_sw_if_index, cp_if_index,
			       ~0);
      pem->dp_if_index_by_sw_if_index[cp_if_index] = dp_if_index;
    }
  else
    {
      pem->cp_if_index_by_sw_if_index[dp_if_index] = ~0;
      pem->dp_if_index_by_sw_if_index[cp_if_index] = ~0;
    }
  return 0;
}

static clib_error_t *
pppoe_add_del_cp_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_add = 1;
  u32 cp_if_index = ~0;
  u32 dp_if_index = ~0;
  clib_error_t *error = NULL;
  vnet_main_t *vnm = vnet_get_main ();

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	{
	  is_add = 0;
  }
    else if (unformat (line_input, "dp %U", unformat_vnet_sw_interface,
      vnm, &dp_if_index));
    else if (unformat (line_input, "cp %U", unformat_vnet_sw_interface,
      vnm, &cp_if_index));
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  break;
	}
    }

  if (cp_if_index == ~0 || dp_if_index == ~0)
    {
      error = clib_error_return (0, "interfaces not specified");
      goto done;
    }

  int rv = pppoe_add_del_cp (cp_if_index, dp_if_index, is_add);
  if (rv == VNET_API_ERROR_ENTRY_ALREADY_EXISTS)
    {
      error = clib_error_return (0, "entry already exists");
      goto done;
    }
  else if (rv == VNET_API_ERROR_INVALID_ARGUMENT)
    {
      error = clib_error_return (0, "invalid argument");
      goto done;
    }
  else if (rv == VNET_API_ERROR_NON_ETHERNET)
    {
      error = clib_error_return (0, "non-ethernet DP interface");
      goto done;
    }


done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (create_pppoe_cp_cmd, static) =
{
    .path = "create pppoe map",
    .short_help = "create pppoe map dp <intfc> cp <intfc> [del]",
    .function = pppoe_add_del_cp_command_fn,
};

static clib_error_t *
pppoe_show_cp_command_fn (vlib_main_t * vm,
        unformat_input_t * input,
        vlib_cli_command_t * cmd)
{
  pppoe_main_t *pem = &pppoe_main;

  if (vec_len(pem->cp_if_index_by_sw_if_index) == 0)
    {
      vlib_cli_output (vm, "No PPPoE control plane interface configured.");
      return 0;
    }
  
  vlib_cli_output (vm, "%-20s%-20s", "Dataplane Interface", "Control Interface");
  vlib_cli_output (vm, "%-20s%-20s", "-------------------", "-----------------");

  for (int i = 0; i < vec_len(pem->cp_if_index_by_sw_if_index); i++)
    {
      if (pem->cp_if_index_by_sw_if_index[i] != ~0)
        {
          vlib_cli_output (vm, "%-20U%-20U",
                    format_vnet_sw_if_index_name, vnet_get_main(), i,
                    format_vnet_sw_if_index_name, vnet_get_main(), pem->cp_if_index_by_sw_if_index[i]);
        }
    }

  return 0;
}

VLIB_CLI_COMMAND (show_pppoe_cp_cmd, static) =
{
  .path = "show pppoe control-plane binding",
  .short_help = "show pppoe control-plane binding",
  .function = pppoe_show_cp_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
