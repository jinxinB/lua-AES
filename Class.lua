
-- ��Ĭ�ϳ�ʼ������ ctor ��Ϊ���ʼ����ʱʹ�ã��Ҵ���ʱ��Ȼ�ᱻ���ã�ctor�����������ڴ�������ʱ����Ĭ�ϱ���
-- �������ʼ��ʱ������ͨ������ǰ��˫�»���"__"��ʽ���ø�����󲢵������е��Զ����ʼ�����������ݲ���
-- ���� ������ �������б�
function Class(className, ...)
    if type(className) ~= "string" then
        error("class name must string type");
    end
    local cls = {__className = className, __isClass = true};
	function cls:ctor() -- defaut Init
	end
	function cls:__ctor() -- On Init
		self["__" .. className] = cls;
		-- �����ʼ��
		if cls.__supers ~= nil then
			local k,super;
            for k,super in pairs(cls.__supers) do
                if type(super) == "table" then
                    super.__ctor(self);
                end
            end
		end
		-- ��ʼ��
		cls.ctor(self);
	end
    local supers = {...};
	local k,super;
	for k,super in ipairs(supers) do
		if type(super) == "table" then
			-- ���Ӹ��б�
			if super.__isClass and type(super.__className) == "string" then
				cls.__supers = cls.__supers or {};
				cls.__supers[super.__className] = super;
				if not cls.__super then
					cls.__super = super;
				end
			else
				error(string.format("create class %s with invalid super class", className));
			end
        else
            error(string.format("create class %s with invalid super class type %s", className, type(super)));
        end
    end
    cls.__index = cls
    if not cls.__supers or #supers == 1 then
        setmetatable(cls, {__index = cls.__super});
    else
        setmetatable(cls, {__index = function (_, key)
			local k,super;
            for k,super in pairs(cls.__supers) do
                if super[key] then
                    return super[key];
                end
            end
        end});
    end
    function cls:new(obj)
        local instance = obj or {};
        setmetatable(instance, {__index = self});
        instance.__class = self;
		instance:__ctor(); -- ��ʼ������
        return instance;
    end
    return cls;
end
