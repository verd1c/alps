// Predicate engine: tokenizer, recursive-descent parser, tree-walking
// evaluator. Values flow through nlohmann::json so field access matches the
// JSON shape produced by DeviceFacts::get_field().
//
// Grammar (Ext. BNF; see docs/RULES.md):
//   predicate := or
//   or        := and       ( '||' and )*
//   and       := unary     ( '&&' unary )*
//   unary     := '!' unary | rel
//   rel       := postfix   ( ( '==' | '!=' | '<' | '<=' | '>' | '>=' ) postfix )?
//   postfix   := primary   ( '.' IDENT ( '(' method_args ')' )? )*
//   primary   := STRING | INTEGER | 'true' | 'false' | 'null'
//              | IDENT '(' args ')'         (top-level function call)
//              | IDENT                       (variable / field root)
//              | '(' expr ')'
//   args      := ε | expr ( ',' expr )*
//   method_args (for '.exists'): IDENT ',' expr
//   method_args (otherwise):     args

#include "alps/engine/predicate.hpp"

#include <algorithm>
#include <cassert>
#include <cctype>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "alps/engine/comparator.hpp"
#include "alps/engine/timeline.hpp"

using nlohmann::json;

namespace alps::engine {

namespace {

    // Token stream.
    enum class Tok {
        EndOfInput,
        LParen,
        RParen,
        Comma,
        Dot,
        String,
        Integer,
        True,
        False,
        Null,
        Ident,
        Not,
        And,
        Or,
        Eq,
        Ne,
        Lt,
        Le,
        Gt,
        Ge,
    };

    struct Token {
        Tok kind = Tok::EndOfInput;
        std::string text; // for String: decoded value; for Integer: digits; for Ident: name
        std::size_t offset = 0;
    };

    class Lexer {
    public:
        explicit Lexer(std::string_view src)
            : src_(src)
        {
        }

        std::vector<Token> tokenize()
        {
            std::vector<Token> out;
            while (pos_ < src_.size()) {
                skip_ws();
                if (pos_ >= src_.size())
                    break;
                const std::size_t start = pos_;
                const char c = src_[pos_];

                if (c == '(') {
                    ++pos_;
                    out.push_back({ Tok::LParen, "(", start });
                    continue;
                }
                if (c == ')') {
                    ++pos_;
                    out.push_back({ Tok::RParen, ")", start });
                    continue;
                }
                if (c == ',') {
                    ++pos_;
                    out.push_back({ Tok::Comma, ",", start });
                    continue;
                }
                if (c == '.') {
                    ++pos_;
                    out.push_back({ Tok::Dot, ".", start });
                    continue;
                }
                if (c == '"' || c == '\'') {
                    out.push_back(read_string(c));
                    continue;
                }
                if (std::isdigit(static_cast<unsigned char>(c))) {
                    out.push_back(read_number());
                    continue;
                }
                if (std::isalpha(static_cast<unsigned char>(c)) || c == '_') {
                    out.push_back(read_ident());
                    continue;
                }
                out.push_back(read_operator());
            }
            out.push_back({ Tok::EndOfInput, "", src_.size() });
            return out;
        }

    private:
        void skip_ws()
        {
            while (pos_ < src_.size()) {
                const char c = src_[pos_];
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    ++pos_;
                    continue;
                }
                // Line comments: '#' to end-of-line; YAML-friendly for predicates
                // that get pasted into rule files.
                if (c == '#') {
                    while (pos_ < src_.size() && src_[pos_] != '\n')
                        ++pos_;
                    continue;
                }
                return;
            }
        }

        [[noreturn]] void fail(std::size_t at, const std::string& msg) const
        {
            std::ostringstream ss;
            ss << "predicate lex error at offset " << at << ": " << msg;
            throw std::runtime_error(ss.str());
        }

        Token read_string(char quote)
        {
            const std::size_t start = pos_;
            ++pos_; // consume opening quote
            std::string val;
            while (pos_ < src_.size() && src_[pos_] != quote) {
                char c = src_[pos_];
                if (c == '\\') {
                    if (pos_ + 1 >= src_.size())
                        fail(pos_, "unterminated escape");
                    char e = src_[pos_ + 1];
                    switch (e) {
                    case 'n':
                        val.push_back('\n');
                        break;
                    case 't':
                        val.push_back('\t');
                        break;
                    case 'r':
                        val.push_back('\r');
                        break;
                    case '\\':
                        val.push_back('\\');
                        break;
                    case '"':
                        val.push_back('"');
                        break;
                    case '\'':
                        val.push_back('\'');
                        break;
                    default:
                        fail(pos_, std::string("unknown escape \\") + e);
                    }
                    pos_ += 2;
                } else {
                    val.push_back(c);
                    ++pos_;
                }
            }
            if (pos_ >= src_.size())
                fail(start, "unterminated string literal");
            ++pos_; // consume closing quote
            return { Tok::String, std::move(val), start };
        }

        Token read_number()
        {
            const std::size_t start = pos_;
            while (pos_ < src_.size() && std::isdigit(static_cast<unsigned char>(src_[pos_])))
                ++pos_;
            return { Tok::Integer, std::string(src_.substr(start, pos_ - start)), start };
        }

        Token read_ident()
        {
            const std::size_t start = pos_;
            while (pos_ < src_.size()) {
                const char c = src_[pos_];
                if (std::isalnum(static_cast<unsigned char>(c)) || c == '_')
                    ++pos_;
                else
                    break;
            }
            std::string name(src_.substr(start, pos_ - start));
            if (name == "true")
                return { Tok::True, name, start };
            if (name == "false")
                return { Tok::False, name, start };
            if (name == "null")
                return { Tok::Null, name, start };
            return { Tok::Ident, std::move(name), start };
        }

        Token read_operator()
        {
            const std::size_t start = pos_;
            const char c = src_[pos_];
            const char n = pos_ + 1 < src_.size() ? src_[pos_ + 1] : '\0';
            auto make = [&](Tok k, std::size_t len, const char* txt) -> Token {
                pos_ += len;
                return { k, txt, start };
            };
            if (c == '=' && n == '=')
                return make(Tok::Eq, 2, "==");
            if (c == '!' && n == '=')
                return make(Tok::Ne, 2, "!=");
            if (c == '<' && n == '=')
                return make(Tok::Le, 2, "<=");
            if (c == '>' && n == '=')
                return make(Tok::Ge, 2, ">=");
            if (c == '<')
                return make(Tok::Lt, 1, "<");
            if (c == '>')
                return make(Tok::Gt, 1, ">");
            if (c == '&' && n == '&')
                return make(Tok::And, 2, "&&");
            if (c == '|' && n == '|')
                return make(Tok::Or, 2, "||");
            if (c == '!')
                return make(Tok::Not, 1, "!");
            fail(pos_, std::string("unexpected character '") + c + "'");
        }

        std::string_view src_;
        std::size_t pos_ = 0;
    };

} // namespace  (close the anon-namespace holding the Lexer)

// AST: a single variant-typed Node. Lives in the alps::engine namespace because
// the header forward-declares `alps::engine::Node` for the pimpl unique_ptr.

using NodePtr = std::unique_ptr<Node>;

enum class NodeKind {
    Literal,
    Ident, // may be a variable binding (env) or a fact field root
    FieldAccess, // obj.field   (no method call)
    MethodCall, // obj.method(args)
    Exists, // obj.exists(var, body)
    FunctionCall, // top-level: affected(x), prop(x), etc.
    UnaryNot,
    BinaryOp,
};

enum class BinOp { Eq, Ne, Lt, Le, Gt, Ge, And, Or };

struct Node {
    NodeKind kind;
    std::size_t offset = 0;

    // Literal
    json literal;

    // Ident / FieldAccess.field / MethodCall.method / FunctionCall.name / Exists.var
    std::string name;

    // For FieldAccess / MethodCall / Exists: the receiver.
    NodePtr receiver;

    // BinaryOp / UnaryNot children.
    NodePtr lhs;
    NodePtr rhs;
    BinOp op = BinOp::Eq;

    // FunctionCall / MethodCall args (for Exists, body is stored in rhs).
    std::vector<NodePtr> args;
};

// Out-of-line special members: Node is complete here, so unique_ptr<Node>'s
// destructor can be instantiated safely.
PredicateAst::PredicateAst() = default;
PredicateAst::~PredicateAst() = default;
PredicateAst::PredicateAst(PredicateAst&&) noexcept = default;
PredicateAst& PredicateAst::operator=(PredicateAst&&) noexcept = default;

namespace { // Parser / Evaluator / lint walker (file-local)

    // Parser.
    class Parser {
    public:
        explicit Parser(std::vector<Token> tokens)
            : toks_(std::move(tokens))
        {
        }

        NodePtr parse_top()
        {
            auto n = parse_or();
            if (peek().kind != Tok::EndOfInput) {
                fail(peek().offset, "unexpected trailing input '" + peek().text + "'");
            }
            return n;
        }

    private:
        // Tokens
        const Token& peek() const { return toks_[i_]; }
        const Token& consume() { return toks_[i_++]; }
        bool accept(Tok k)
        {
            if (peek().kind == k) {
                ++i_;
                return true;
            }
            return false;
        }
        const Token& expect(Tok k, const char* what)
        {
            if (peek().kind != k)
                fail(
                    peek().offset, std::string("expected ") + what + ", got '" + peek().text + "'");
            return toks_[i_++];
        }

        [[noreturn]] void fail(std::size_t at, const std::string& msg) const
        {
            std::ostringstream ss;
            ss << "predicate parse error at offset " << at << ": " << msg;
            throw std::runtime_error(ss.str());
        }

        NodePtr parse_or()
        {
            auto lhs = parse_and();
            while (accept(Tok::Or)) {
                auto rhs = parse_and();
                auto n = std::make_unique<Node>();
                n->kind = NodeKind::BinaryOp;
                n->op = BinOp::Or;
                n->lhs = std::move(lhs);
                n->rhs = std::move(rhs);
                lhs = std::move(n);
            }
            return lhs;
        }

        NodePtr parse_and()
        {
            auto lhs = parse_unary();
            while (accept(Tok::And)) {
                auto rhs = parse_unary();
                auto n = std::make_unique<Node>();
                n->kind = NodeKind::BinaryOp;
                n->op = BinOp::And;
                n->lhs = std::move(lhs);
                n->rhs = std::move(rhs);
                lhs = std::move(n);
            }
            return lhs;
        }

        NodePtr parse_unary()
        {
            if (accept(Tok::Not)) {
                auto inner = parse_unary();
                auto n = std::make_unique<Node>();
                n->kind = NodeKind::UnaryNot;
                n->lhs = std::move(inner);
                return n;
            }
            return parse_rel();
        }

        NodePtr parse_rel()
        {
            auto lhs = parse_postfix();
            BinOp op = BinOp::Eq;
            bool have = false;
            switch (peek().kind) {
            case Tok::Eq:
                op = BinOp::Eq;
                have = true;
                break;
            case Tok::Ne:
                op = BinOp::Ne;
                have = true;
                break;
            case Tok::Lt:
                op = BinOp::Lt;
                have = true;
                break;
            case Tok::Le:
                op = BinOp::Le;
                have = true;
                break;
            case Tok::Gt:
                op = BinOp::Gt;
                have = true;
                break;
            case Tok::Ge:
                op = BinOp::Ge;
                have = true;
                break;
            default:
                break;
            }
            if (!have)
                return lhs;
            consume();
            auto rhs = parse_postfix();
            auto n = std::make_unique<Node>();
            n->kind = NodeKind::BinaryOp;
            n->op = op;
            n->lhs = std::move(lhs);
            n->rhs = std::move(rhs);
            return n;
        }

        NodePtr parse_postfix()
        {
            auto recv = parse_primary();
            while (accept(Tok::Dot)) {
                const auto& id_tok = expect(Tok::Ident, "identifier after '.'");
                const std::string id = id_tok.text;

                if (accept(Tok::LParen)) {
                    // Method call.
                    if (id == "exists") {
                        // Special form: first arg must be a bare identifier (variable name).
                        if (peek().kind != Tok::Ident) {
                            fail(peek().offset, "first arg to .exists() must be an identifier");
                        }
                        const std::string var = consume().text;
                        expect(Tok::Comma, "','");
                        auto body = parse_or();
                        expect(Tok::RParen, "')'");
                        auto n = std::make_unique<Node>();
                        n->kind = NodeKind::Exists;
                        n->offset = id_tok.offset;
                        n->receiver = std::move(recv);
                        n->name = var; // bound variable name
                        n->rhs = std::move(body);
                        recv = std::move(n);
                    } else {
                        // Regular method call.
                        std::vector<NodePtr> args;
                        if (peek().kind != Tok::RParen) {
                            args.push_back(parse_or());
                            while (accept(Tok::Comma))
                                args.push_back(parse_or());
                        }
                        expect(Tok::RParen, "')'");
                        auto n = std::make_unique<Node>();
                        n->kind = NodeKind::MethodCall;
                        n->offset = id_tok.offset;
                        n->receiver = std::move(recv);
                        n->name = id;
                        n->args = std::move(args);
                        recv = std::move(n);
                    }
                } else {
                    // Field access.
                    auto n = std::make_unique<Node>();
                    n->kind = NodeKind::FieldAccess;
                    n->offset = id_tok.offset;
                    n->receiver = std::move(recv);
                    n->name = id;
                    recv = std::move(n);
                }
            }
            return recv;
        }

        NodePtr parse_primary()
        {
            const Token t = peek();
            switch (t.kind) {
            case Tok::String: {
                consume();
                auto n = std::make_unique<Node>();
                n->kind = NodeKind::Literal;
                n->offset = t.offset;
                n->literal = t.text;
                return n;
            }
            case Tok::Integer: {
                consume();
                auto n = std::make_unique<Node>();
                n->kind = NodeKind::Literal;
                n->offset = t.offset;
                try {
                    n->literal = static_cast<int64_t>(std::stoll(t.text));
                } catch (...) {
                    fail(t.offset, "integer out of range: " + t.text);
                }
                return n;
            }
            case Tok::True:
            case Tok::False: {
                consume();
                auto n = std::make_unique<Node>();
                n->kind = NodeKind::Literal;
                n->offset = t.offset;
                n->literal = (t.kind == Tok::True);
                return n;
            }
            case Tok::Null: {
                consume();
                auto n = std::make_unique<Node>();
                n->kind = NodeKind::Literal;
                n->offset = t.offset;
                n->literal = nullptr;
                return n;
            }
            case Tok::LParen: {
                consume();
                auto e = parse_or();
                expect(Tok::RParen, "')'");
                return e;
            }
            case Tok::Ident: {
                consume();
                if (accept(Tok::LParen)) {
                    std::vector<NodePtr> args;
                    if (peek().kind != Tok::RParen) {
                        args.push_back(parse_or());
                        while (accept(Tok::Comma))
                            args.push_back(parse_or());
                    }
                    expect(Tok::RParen, "')'");
                    auto n = std::make_unique<Node>();
                    n->kind = NodeKind::FunctionCall;
                    n->offset = t.offset;
                    n->name = t.text;
                    n->args = std::move(args);
                    return n;
                }
                auto n = std::make_unique<Node>();
                n->kind = NodeKind::Ident;
                n->offset = t.offset;
                n->name = t.text;
                return n;
            }
            default:
                fail(t.offset, std::string("unexpected token '") + t.text + "'");
            }
        }

        std::vector<Token> toks_;
        std::size_t i_ = 0;
    };

    // Evaluator.
    using Env = std::vector<std::pair<std::string, json>>;

    json lookup_env(const Env& env, const std::string& name)
    {
        for (auto it = env.rbegin(); it != env.rend(); ++it) {
            if (it->first == name)
                return it->second;
        }
        return json {}; // sentinel; caller distinguishes "not found" via `is_variable_bound`
    }

    bool is_bound(const Env& env, const std::string& name)
    {
        for (auto it = env.rbegin(); it != env.rend(); ++it) {
            if (it->first == name)
                return true;
        }
        return false;
    }

    // Convert a json value to a string suitable for a comparator. Numbers become
    // their decimal representation. Booleans and nulls are rejected; comparators
    // operate on version-like strings only.
    std::string json_to_version_string(const json& v)
    {
        if (v.is_string())
            return v.get<std::string>();
        if (v.is_number_integer())
            return std::to_string(v.get<int64_t>());
        if (v.is_number_unsigned())
            return std::to_string(v.get<uint64_t>());
        throw std::runtime_error("cannot coerce JSON value to version string");
    }

    // A comparison predicate on two JSON values. For strings and numbers we
    // implement typed compare. For null == null, true. For mismatched-type
    // comparisons other than equality, throws.
    int json_cmp(const json& a, const json& b)
    {
        if (a.is_null() && b.is_null())
            return 0;
        if (a.is_null() || b.is_null()) {
            throw std::runtime_error("cannot compare null with non-null (except with == / !=)");
        }
        if (a.is_boolean() && b.is_boolean()) {
            return a.get<bool>() == b.get<bool>() ? 0 : (a.get<bool>() ? 1 : -1);
        }
        if (a.is_number() && b.is_number()) {
            const double da = a.get<double>();
            const double db = b.get<double>();
            return da < db ? -1 : (da > db ? 1 : 0);
        }
        if (a.is_string() && b.is_string()) {
            const auto& sa = a.get_ref<const std::string&>();
            const auto& sb = b.get_ref<const std::string&>();
            return sa == sb ? 0 : (sa < sb ? -1 : 1);
        }
        throw std::runtime_error("type mismatch: cannot order " + std::string(a.type_name())
            + " and " + std::string(b.type_name()));
    }

    bool json_eq(const json& a, const json& b)
    {
        // nlohmann/json's operator== does the right thing for us: null==null is true,
        // int==float compares numerically, arrays/objects deep-compare.
        return a == b;
    }

    class Evaluator {
    public:
        Evaluator(const EvalContext& ctx)
            : ctx_(ctx)
        {
        }

        json eval(const Node& n, Env& env)
        {
            switch (n.kind) {
            case NodeKind::Literal:
                return n.literal;

            case NodeKind::Ident: {
                if (is_bound(env, n.name))
                    return lookup_env(env, n.name);
                if (ctx_.facts)
                    return ctx_.facts->get_field(n.name);
                return json {};
            }

            case NodeKind::FieldAccess: {
                const json obj = eval(*n.receiver, env);
                if (obj.is_null())
                    return json {};
                if (!obj.is_object()) {
                    // Try walking into the string as a dotted path for the top-level
                    // ident case where we already got the parent object serialized.
                    // Otherwise, field-access into non-object yields null.
                    return json {};
                }
                auto it = obj.find(n.name);
                return (it != obj.end()) ? *it : json {};
            }

            case NodeKind::UnaryNot: {
                json v = eval(*n.lhs, env);
                if (!v.is_boolean()) {
                    throw std::runtime_error("operator ! requires a boolean operand");
                }
                return !v.get<bool>();
            }

            case NodeKind::BinaryOp: {
                if (n.op == BinOp::And) {
                    json l = eval(*n.lhs, env);
                    if (!l.is_boolean())
                        throw std::runtime_error("&& requires boolean lhs");
                    if (!l.get<bool>())
                        return false; // short-circuit
                    json r = eval(*n.rhs, env);
                    if (!r.is_boolean())
                        throw std::runtime_error("&& requires boolean rhs");
                    return r.get<bool>();
                }
                if (n.op == BinOp::Or) {
                    json l = eval(*n.lhs, env);
                    if (!l.is_boolean())
                        throw std::runtime_error("|| requires boolean lhs");
                    if (l.get<bool>())
                        return true;
                    json r = eval(*n.rhs, env);
                    if (!r.is_boolean())
                        throw std::runtime_error("|| requires boolean rhs");
                    return r.get<bool>();
                }
                json l = eval(*n.lhs, env);
                json r = eval(*n.rhs, env);
                switch (n.op) {
                case BinOp::Eq:
                    return json_eq(l, r);
                case BinOp::Ne:
                    return !json_eq(l, r);
                case BinOp::Lt:
                    return json_cmp(l, r) < 0;
                case BinOp::Le:
                    return json_cmp(l, r) <= 0;
                case BinOp::Gt:
                    return json_cmp(l, r) > 0;
                case BinOp::Ge:
                    return json_cmp(l, r) >= 0;
                default:
                    break;
                }
                throw std::runtime_error("unreachable BinaryOp");
            }

            case NodeKind::FunctionCall: {
                if (n.name == "affected") {
                    if (n.args.size() != 1)
                        throw std::runtime_error("affected() takes exactly one argument");
                    json arg = eval(*n.args[0], env);
                    if (!arg.is_string())
                        throw std::runtime_error("affected(field) requires a string field name");
                    return call_affected(arg.get<std::string>());
                }
                if (n.name == "prop") {
                    if (n.args.size() != 1)
                        throw std::runtime_error("prop() takes exactly one argument");
                    json arg = eval(*n.args[0], env);
                    if (!arg.is_string())
                        throw std::runtime_error("prop(key) requires a string key");
                    return call_prop(arg.get<std::string>());
                }
                throw std::runtime_error("unknown function: " + n.name);
            }

            case NodeKind::MethodCall: {
                json recv = eval(*n.receiver, env);
                if (n.name == "contains") {
                    if (n.args.size() != 1)
                        throw std::runtime_error(".contains() takes exactly one argument");
                    json arg = eval(*n.args[0], env);
                    if (recv.is_array()) {
                        for (const auto& item : recv) {
                            if (json_eq(item, arg))
                                return true;
                        }
                        return false;
                    }
                    if (recv.is_string() && arg.is_string()) {
                        return recv.get<std::string>().find(arg.get<std::string>())
                            != std::string::npos;
                    }
                    throw std::runtime_error(".contains() needs a list or string receiver");
                }
                throw std::runtime_error("unknown method: " + n.name);
            }

            case NodeKind::Exists: {
                json recv = eval(*n.receiver, env);
                if (!recv.is_array()) {
                    throw std::runtime_error(".exists() needs a list receiver");
                }
                env.emplace_back(n.name, json {});
                try {
                    for (const auto& item : recv) {
                        env.back().second = item;
                        json b = eval(*n.rhs, env);
                        if (!b.is_boolean()) {
                            throw std::runtime_error(".exists() body must return bool");
                        }
                        if (b.get<bool>()) {
                            env.pop_back();
                            return true;
                        }
                    }
                } catch (...) {
                    env.pop_back();
                    throw;
                }
                env.pop_back();
                return false;
            }
            }
            throw std::runtime_error("unreachable NodeKind");
        }

    private:
        // Resolve `affected("X")` by finding the AffectedField named X in the rule
        // and running the Layer-1 timeline against the current device's value at
        // that field. Missing device value yields false (no evidence of vulnerability).
        // Missing rule field throws (rule author bug; caught by rules-lint).
        //
        // Downgrade hypothesis: if ctx.assume_affected is set, every declared
        // field short-circuits to true; the caller is asking "would this rule
        // apply if the device rolled back to a vulnerable firmware?".
        bool call_affected(const std::string& field)
        {
            if (!ctx_.rule) {
                throw std::runtime_error("affected(): no rule bound to eval context");
            }
            const alps::core::AffectedField* found = nullptr;
            for (const auto& af : ctx_.rule->affected) {
                if (af.field == field) {
                    found = &af;
                    break;
                }
            }
            if (!found) {
                throw std::runtime_error(
                    "affected(\"" + field + "\"): field not declared in rule.affected[]");
            }
            if (ctx_.assume_affected)
                return true;
            if (!ctx_.facts)
                return false;
            json v = ctx_.facts->get_field(field);
            if (v.is_null())
                return false;
            std::string ver;
            try {
                ver = json_to_version_string(v);
            } catch (...) {
                return false;
            }
            return timeline_affected(found->type, found->events, ver);
        }

        std::string call_prop(const std::string& key)
        {
            if (!ctx_.facts)
                return {};
            auto it = ctx_.facts->raw_props.find(key);
            return it == ctx_.facts->raw_props.end() ? std::string {} : it->second;
        }

        const EvalContext& ctx_;
    };

    // Lint walker: traverses the AST looking for structural errors reachable
    // without a device fact sheet.
    void lint_walk(const Node& n, const alps::core::Rule& rule)
    {
        switch (n.kind) {
        case NodeKind::Literal:
        case NodeKind::Ident:
            return;
        case NodeKind::FieldAccess:
            lint_walk(*n.receiver, rule);
            return;
        case NodeKind::UnaryNot:
            lint_walk(*n.lhs, rule);
            return;
        case NodeKind::BinaryOp:
            lint_walk(*n.lhs, rule);
            lint_walk(*n.rhs, rule);
            return;
        case NodeKind::MethodCall:
            lint_walk(*n.receiver, rule);
            if (n.name != "contains") {
                throw std::runtime_error(
                    "unknown method '" + n.name + "' at offset " + std::to_string(n.offset));
            }
            for (const auto& a : n.args)
                lint_walk(*a, rule);
            return;
        case NodeKind::Exists:
            lint_walk(*n.receiver, rule);
            lint_walk(*n.rhs, rule);
            return;
        case NodeKind::FunctionCall:
            for (const auto& a : n.args)
                lint_walk(*a, rule);
            if (n.name == "affected") {
                if (n.args.size() != 1)
                    throw std::runtime_error("affected() takes exactly one argument");
                if (n.args[0]->kind != NodeKind::Literal || !n.args[0]->literal.is_string()) {
                    throw std::runtime_error(
                        "affected() argument must be a string literal (for lint)");
                }
                const std::string field = n.args[0]->literal.get<std::string>();
                bool ok = false;
                for (const auto& af : rule.affected) {
                    if (af.field == field) {
                        // Also validate every event version parses.
                        auto cmp = make_comparator(af.type);
                        for (const auto& e : af.events) {
                            if (e.introduced)
                                cmp->validate(*e.introduced);
                            if (e.fixed)
                                cmp->validate(*e.fixed);
                            if (e.last_affected)
                                cmp->validate(*e.last_affected);
                            if (e.limit)
                                cmp->validate(*e.limit);
                        }
                        ok = true;
                        break;
                    }
                }
                if (!ok) {
                    throw std::runtime_error(
                        "affected(\"" + field + "\"): field not declared in rule.affected[]");
                }
            } else if (n.name == "prop") {
                if (n.args.size() != 1)
                    throw std::runtime_error("prop() takes exactly one argument");
            } else {
                throw std::runtime_error(
                    "unknown function '" + n.name + "' at offset " + std::to_string(n.offset));
            }
            return;
        }
    }

} // namespace

// Public API impl.
std::unique_ptr<PredicateAst> parse_predicate(std::string_view src)
{
    auto ast = std::make_unique<PredicateAst>();
    ast->source = std::string(src);
    Lexer lex(src);
    Parser parser(lex.tokenize());
    ast->root = parser.parse_top();
    return ast;
}

void lint_predicate(const PredicateAst& ast, const alps::core::Rule& rule)
{
    if (!ast.root)
        throw std::runtime_error("empty predicate");
    lint_walk(*ast.root, rule);
}

bool evaluate_predicate(const PredicateAst& ast, const EvalContext& ctx)
{
    if (!ast.root)
        throw std::runtime_error("empty predicate");
    Evaluator ev(ctx);
    Env env;
    json out = ev.eval(*ast.root, env);
    if (!out.is_boolean()) {
        throw std::runtime_error("predicate must evaluate to a boolean");
    }
    return out.get<bool>();
}

bool evaluate_predicate_str(std::string_view src, const EvalContext& ctx)
{
    auto ast = parse_predicate(src);
    return evaluate_predicate(*ast, ctx);
}

} // namespace alps::engine
