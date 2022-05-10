
require'Class'
BaseFun_AES = Class("AES");

function BaseFun_AES:ctor()
	self.N_ROW = 4;
	self.N_COL = 4;
	self.N_BLOCK = self.N_ROW * self.N_COL;
	self.N_MAX_ROUNDS = 14;
	self.KEY_SCHEDULE_BYTES = ((self.N_MAX_ROUNDS + 1) * self.N_BLOCK);
	self.key_sched = {};
	self.round = 0;
end
BaseFun_AES.s_fwd = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};
BaseFun_AES.s_inv = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};
function BaseFun_AES.f2(x)
	if (x&0x80) ~= 0 then
		return ((x << 1) ~ 0x011B) & 0xFF; -- WPOLY
	else
		return (x << 1) & 0xFF;
	end
end
function BaseFun_AES.d2(x)
	if (x&0x01) ~= 0 then
		return (x >> 1) ~ 0x8D; -- DPOLY
	else
		return (x >> 1);
	end
end
function BaseFun_AES:xor_block(d , dPos , s , sPos)
	local i;
	for i = 1 , self.N_BLOCK do
		d[dPos+i-1] = d[dPos+i-1] ~ s[sPos+i-1];
	end
end
function BaseFun_AES:copy_and_key(d , dPos , s , sPos , k , kPos)
	local i;
	for i = 1 , self.N_BLOCK do
		d[dPos+i-1] = s[sPos+i-1] ~ k[kPos+i-1];
	end
end
function BaseFun_AES.copy_n_bytes(d , dPos , s , sPos , cnt)
	local i;
	for i = 1 , cnt do
		d[dPos+i-1] = s[sPos+i-1];
	end
end
function BaseFun_AES.StrToList(str)
end
function BaseFun_AES.StrToList(str)
end

function BaseFun_AES:s_box(x)
	return self.s_fwd[x+1];
end
function BaseFun_AES:is_box(x)
	return self.s_inv[x+1];
end
function BaseFun_AES:shift_sub_rows(st)
	local tt;
	st[1] = self:s_box(st[1]);
	st[5] = self:s_box(st[5]);
	st[9] = self:s_box(st[9]);
	st[13] = self:s_box(st[13]);
	
	tt = st[2];
	st[2] = self:s_box(st[6]);
	st[6] = self:s_box(st[10]);
	st[10] = self:s_box(st[14]);
	st[14] = self:s_box(tt);
	
	tt = st[3];
	st[3] = self:s_box(st[11]);
	st[11] = self:s_box(tt);
	tt = st[7];
	st[7] = self:s_box(st[15]);
	st[15] = self:s_box(tt);
	
	tt = st[16];
	st[16] = self:s_box(st[12]);
	st[12] = self:s_box(st[8]);
	st[8] = self:s_box(st[4]);
	st[4] = self:s_box(tt);
end
function BaseFun_AES:inv_shift_sub_rows(st)
	local tt;
	st[1] = self:is_box(st[1]);
	st[5] = self:is_box(st[5]);
	st[9] = self:is_box(st[9]);
	st[13] = self:is_box(st[13]);
	
	tt = st[14];
	st[14] = self:is_box(st[10]);
	st[10] = self:is_box(st[6]);
	st[6] = self:is_box(st[2]);
	st[2] = self:is_box(tt);
	
	tt = st[3];
	st[3] = self:is_box(st[11]);
	st[11] = self:is_box(tt);
	tt = st[7];
	st[7] = self:is_box(st[15]);
	st[15] = self:is_box(tt);
	
	tt = st[4];
	st[4] = self:is_box(st[8]);
	st[8] = self:is_box(st[12]);
	st[12] = self:is_box(st[16]);
	st[16] = self:is_box(tt);
end
function BaseFun_AES:mix_sub_columns(dt , st)
	local i , j , k , l , a , b , c , d , a1 , a2 , b1 , b2 , c1 , c2 , d1 , d2;
	j = 6;
	k = 11;
	l = 16;
	for i = 1 , self.N_BLOCK , self.N_COL do
		a = st[i];
		b = st[j];
		j = ((j+self.N_COL-1) & 15) + 1;
		c = st[k];
		k = ((k+self.N_COL-1) & 15) + 1;
		d = st[l];
		l = ((l+self.N_COL-1) & 15) + 1;
		a1 = self:s_box(a);
		b1 = self:s_box(b);
		c1 = self:s_box(c); 
		d1 = self:s_box(d);
		a2 = self.f2(a1);
		b2 = self.f2(b1);
		c2 = self.f2(c1);
		d2 = self.f2(d1);
		dt[i]   = a2     ~  b2~b1  ~  c1     ~  d1;
		dt[i+1] = a1     ~  b2     ~  c2~c1  ~  d1;
		dt[i+2] = a1     ~  b1     ~  c2     ~  d2~d1;
		dt[i+3] = a2~a1  ~  b1     ~  c1     ~  d2;
	end
end
function BaseFun_AES:inv_mix_sub_columns(dt , st)
	local i , a1 , b1 , c1 , d1 , a2 , b2 , c2 , d2 , a4 , b4 , c4 , d4 , a8 , b8 , c8 , d8 , a9 , b9 , c9 , d9 , ac , bc , cc , dc;
	for  i = 1 , self.N_BLOCK , self.N_COL do
		a1 = st [i];
		b1 = st [i+1];
		c1 = st [i+2];
		d1 = st [i+3];
		
		a2 = self.f2(a1);
		b2 = self.f2(b1);
		c2 = self.f2(c1);
		d2 = self.f2(d1);
		
		a4 = self.f2(a2);
		b4 = self.f2(b2);
		c4 = self.f2(c2);
		d4 = self.f2(d2);
		
		a8 = self.f2(a4);
		b8 = self.f2(b4);
		c8 = self.f2(c4);
		d8 = self.f2(d4);
		
		a9 = a8 ~ a1;
		b9 = b8 ~ b1;
		c9 = c8 ~ c1;
		d9 = d8 ~ d1;
		
		ac = a8 ~ a4;
		bc = b8 ~ b4;
		cc = c8 ~ c4;
		dc = d8 ~ d4;

		dt[i]             = self:is_box(ac~a2  ~  b9~b2  ~  cc~c1  ~  d9);
		dt[((i+4)&15)+1]  = self:is_box(a9     ~  bc~b2  ~  c9~c2  ~  dc~d1);
		dt[((i+9)&15)+1]  = self:is_box(ac~a1  ~  b9     ~  cc~c2  ~  d9~d2);
		dt[((i+14)&15)+1] = self:is_box(a9~a2  ~  bc~b1  ~  c9     ~  dc~d2);
	end
end
function BaseFun_AES:set_key(key , keylen)
	if keylen == 16 then
		self.round = 10;
	elseif keylen == 24 then
		self.round = 12;
	elseif keylen == 32 then
		self.round = 14;
	else
		self.round = 0;
		return false;
	end
	local hi ,  t , nNext , cc , rc , i , tt , ttt;
	hi = (self.round + 1) << 4;
	self.copy_n_bytes(self.key_sched , 1 , key , 1 , keylen);
	nNext = keylen;
	
	t = {};
	cc = keylen;
	rc = 1;
	while cc < hi do
		self.copy_n_bytes(t , 1 , self.key_sched , cc-3 , self.N_COL);
		if cc == nNext then
			nNext = nNext + keylen;
			ttt = t[1];
			t[1] = self:s_box(t[2]) ~ rc;
			t[2] = self:s_box(t[3]);
			t[3] = self:s_box(t[4]);
			t[4] = self:s_box(ttt);
			rc = self.f2(rc);
		elseif keylen == 32 and (cc & 31) == 16 then
			t[1] = self:s_box(t[1]);
			t[2] = self:s_box(t[2]);
			t[3] = self:s_box(t[3]);
			t[4] = self:s_box(t[4]);
		end
		tt = cc - keylen;
		for i = 1 , self.N_COL do
			self.key_sched[cc + i] = self.key_sched[tt + i] ~ t[i];
		end
		cc = cc + self.N_COL;
	end
	return true;
end
function BaseFun_AES:encrypt(plain , pPos , cipher , cPos)
	local r , s1 , s2;
	s1 = {};
	s2 = {};
	self:copy_and_key(s1 , 1 , plain , pPos , self.key_sched , 1);
	for r = 1 , self.round - 1 do
		self:mix_sub_columns(s2 , s1);
		self:copy_and_key(s1 , 1 , s2 , 1 , self.key_sched , 1 + (r * self.N_BLOCK));
	end
	self:shift_sub_rows(s1);
	self:copy_and_key(cipher , cPos , s1 , 1 , self.key_sched , 1 + (self.round * self.N_BLOCK));
end
function BaseFun_AES:decrypt(cipher , pPos , plain , cPos)
	local r , s1 , s2;
	s1 = {};
	s2 = {};
	self:copy_and_key(s1 , 1 , cipher , pPos , self.key_sched , 1 + (self.round * self.N_BLOCK));
	self:inv_shift_sub_rows(s1);
	for r = self.round - 1 , 1 , -1 do
		self:copy_and_key(s2 , 1 , s1 , 1 , self.key_sched , 1 + (r * self.N_BLOCK));
		self:inv_mix_sub_columns(s1 , s2);
	end
	self:copy_and_key(plain , cPos , s1 , 1 , self.key_sched , 1);
end
function BaseFun_AES.GetStringList(strBytes)
	local i , List;
	List = {};
	for i = 1 , string.len(strBytes) do
		List[i] = string.byte(strBytes , i);
	end
	return List;
end
function BaseFun_AES.GetStringKey(strKey)
	local i , nLen , nKeyLen , List;
	nLen = string.len(strKey);
	if nLen <= 16 then
		nKeyLen = 16;
	elseif nLen <= 24 then
		nKeyLen = 24;
	else
		nKeyLen = 32;
	end
	List = {};
	for i = 1 , nKeyLen do
		if i <= nLen then
			List[i] = string.byte(strKey , i);
		else
			List[i] = 0; -- 零填充
		end
	end
	return List;
end
function BaseFun_AES:GetBlockList(strData)
	local i , nLen , nDataLen , List;
	nLen = string.len(strData);
	if (nLen%self.N_BLOCK) ~= 0 then
		nDataLen = (math.floor(nLen/self.N_BLOCK) + 1) * self.N_BLOCK;
	else
		nDataLen = nLen;
	end
	List = {};
	for i = 1 , nDataLen do
		if i <= nLen then
			List[i] = string.byte(strData , i);
		else
			List[i] = 0; -- 零填充
		end
	end
	return List;
end
function BaseFun_AES:ecb_EncryptDecrypt(strData , strKey , bEncrypt)
	local i , List , reList;
	if type(strData) ~= "string" or type(strKey) ~= "string" then
		return;
	end
	-- if strData == "" then
		-- return "";
	-- end
	List = self.GetStringKey(strKey);
	self:set_key(List , #List);
	List = self:GetBlockList(strData);
	reList = {};
	if bEncrypt then
		for i = 1 , #List , self.N_BLOCK do
			self:encrypt(List , i , reList , i);
		end
	else
		for i = 1 , #List , self.N_BLOCK do
			self:decrypt(List , i , reList , i);
		end
	end
	local k , txt , txtList; -- i , 
	txtList = {};
	txt = "";
	k = 0;
	for i = 1 , #reList do
		txt = txt .. string.char(reList[i]);
		k = k + 1;
		if k > 64 then
			table.insert(txtList , txt);
			k = 0;
			txt = "";
		end
	end
	table.insert(txtList , txt);
	return table.concat(txtList);
	-- return string.char(table.unpack(reList));
end
function BaseFun_AES:cbc_EncryptDecrypt(strData , strKey , strIV , bEncrypt)
	local i , List , ivList , tmpList , reList;
	if type(strData) ~= "string" or type(strKey) ~= "string" then
		return;
	end
	List = self.GetStringKey(strKey);
	self:set_key(List , #List);
	List = self:GetBlockList(strData);
	ivList = self:GetBlockList(strIV);
	reList = {};
	if bEncrypt then
		for i = 1 , #List , self.N_BLOCK do
			self:xor_block(ivList , 1 , List , i);
			self:encrypt(ivList , 1 , reList , i);
			self.copy_n_bytes(ivList , 1 , reList , i , self.N_BLOCK);
		end
	else
		tmpList = {};
		for i = 1 , #List , self.N_BLOCK do
			self.copy_n_bytes(tmpList , 1 , List , i , self.N_BLOCK);
			self:decrypt(List , i , reList , i);
			self:xor_block(reList , i , ivList , 1);
			self.copy_n_bytes(ivList , 1 , tmpList , 1 , self.N_BLOCK);
		end
	end
	local k , txt , txtList; -- i , 
	txtList = {};
	txt = "";
	k = 0;
	for i = 1 , #reList do
		txt = txt .. string.char(reList[i]);
		k = k + 1;
		if k > 64 then
			table.insert(txtList , txt);
			k = 0;
			txt = "";
		end
	end
	table.insert(txtList , txt);
	return table.concat(txtList);
	-- return string.char(table.unpack(reList));
end

return BaseFun_AES