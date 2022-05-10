
-- 类默认初始化函数 ctor 仅为类初始对象时使用，且创建时必然会被调用，ctor函数可用来在创建对象时构建默认变量
-- 在子类初始化时，可以通过类名前加双下划线"__"显式引用父类对象并调用其中的自定义初始化函数来传递参数
-- 参数 ：类名 ，父类列表
function Class(className, ...)
    if type(className) ~= "string" then
        error("class name must string type");
    end
    local cls = {__className = className, __isClass = true};
	function cls:ctor() -- defaut Init
	end
	function cls:__ctor() -- On Init
		self["__" .. className] = cls;
		-- 父类初始化
		if cls.__supers ~= nil then
			local k,super;
            for k,super in pairs(cls.__supers) do
                if type(super) == "table" then
                    super.__ctor(self);
                end
            end
		end
		-- 初始化
		cls.ctor(self);
	end
    local supers = {...};
	local k,super;
	for k,super in ipairs(supers) do
		if type(super) == "table" then
			-- 附加父列表
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
		instance:__ctor(); -- 初始化调用
        return instance;
    end
    return cls;
end
